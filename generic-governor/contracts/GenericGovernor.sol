// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//   https://hazbase.com

import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorSettingsUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorVotesUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorCountingSimpleUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorTimelockControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/TimelockControllerUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/governance/utils/IVotes.sol";

import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";
import "./Strategy.sol";

/**
 *  @title GenericGovernor
 *
 *  @notice
 *  - Purpose: Strategy-pluggable, timestamped-window Governor built on OpenZeppelin’s Governor stack.
 *    Supports economy/social modes by delegating voting **weight** to an external `IWeightStrategy`.
 *  - Key ideas:
 *      * Externalizable weight: `_getVotes()` calls `IWeightStrategy.weight(voter, blockNumber, token, data)`.
 *      * Explicit voting window: proposals specify absolute `{startTs, endTs}` (≤ 60 days span).
 *      * Timelock execution: via `GovernorTimelockControlUpgradeable`.
 *      * Meta-governance: `proposeChild` records a shared id & origin for cross-governance orchestration.
 *  - Governance surface:
 *      * `updateStrategy` (onlyGovernance) — swap default weight strategy on-chain.
 *      * `propose(proposer, targets, values, calldatas, description, startTs, endTs)` — create proposal with window.
 *  - Security / Audit Notes:
 *      * Strategy call is a `staticcall`; on failure reverts `StrategyFailed()`. Return value is bounds-checked (`> 1e36` → `Overflow()`).
 *      * Proposal threshold is fetched from strategy (`minThreshold()`); uses Governor’s standard `GovernorInsufficientProposerVotes` error.
 *      * Voting window overrides Governor’s default state machine in `state()` (Pending/Active until endTs, then Succeeded/Defeated).
 *      * Upgrades are gated by `onlyGovernance` (on-chain vote required).
 */

contract GenericGovernor is
    Initializable,
    GovernorSettingsUpgradeable,
    GovernorVotesUpgradeable,
    GovernorCountingSimpleUpgradeable,
    GovernorTimelockControlUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    /*──────────────────── Errors ─────────────────────*/
    error StrategyMissing();
    error IdMismatch();
    error InvalidTime();
    error NoStrategy();
    error SharedIdMismatch();
    error StrategyFailed();
    error Overflow();

    /*──────────────────── Enums / Events ─────────────────────*/
    /// @notice Emitted when a (default) strategy is changed.
    event StrategyRegistered(bytes4 indexed id, address indexed strat); // (declared for future use)
    event DefaultStrategySet(bytes4 indexed id, address indexed strat);

    /// @notice Role for meta-governance helper that can mirror child proposals.
    bytes32 public constant META_ROLE = keccak256("META_ROLE");

    /// @notice Distinguishes locally-originated vs meta-governance proposals.
    enum Origin { Standalone, Meta }
    mapping(uint256 => Origin) public proposalOrigin;

    /*──────────────────── Storage ─────────────────────────────*/
    /// @notice Default weight strategy if not otherwise overridden.
    IWeightStrategy public defaultStrategy;

    /// @dev In-memory snapshot of a proposal as created through the extended `propose`.
    struct Proposal {
        uint256 proposalId;
        address proposer;
        address[] targets;
        uint256[] values;
        bytes[] calldatas;
        uint64 start;
        uint64 end;
        string description;
    }

    /// @dev Start/End timestamps backing the custom state machine.
    struct ProposalTime { uint64 start; uint64 end; }
    mapping(uint256 => ProposalTime) private _timeWindows;

    /// @notice proposalId => Proposal details
    mapping(uint256 => Proposal) public proposals;

    /*──────────────────── Constructor ─────────────────────────*/
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    /*──────────────────── Initializer ─────────────────────────*/

    /**
     * @notice Initialize the Governor instance.
     * @param admin       Admin for RolesCommon / ERC2771 forwarder management.
     * @param name_       Governor name.
     * @param token_      IVotes-compatible governance token (e.g., ERC20Votes).
     * @param timelock_   Timelock controller for queued execution.
     * @param strategyAddr Address of initial `IWeightStrategy` implementation.
     * @param forwarders  Trusted ERC-2771 forwarders.
     *
     * @dev
     * - Default GovernorSettings: votingDelay=0, votingPeriod=365 days, proposalThreshold=0.
     * - Reverts StrategyMissing if `strategyAddr` is zero.
     */
    function initialize(
        address admin,
        string memory name_,
        IVotes token_,
        TimelockControllerUpgradeable timelock_,
        address strategyAddr,
        address[] calldata forwarders
    ) external initializer {
        if( strategyAddr == address(0) ) revert StrategyMissing();

        __Governor_init(name_);
        __GovernorSettings_init(0, 60 * 60 * 24 * 365, 0);
        __GovernorVotes_init(token_);
        __GovernorCountingSimple_init();
        __GovernorTimelockControl_init(timelock_);
        __ERC2771Context_init(forwarders);
        __UUPSUpgradeable_init();
        __RolesCommon_init(admin);

        defaultStrategy = IWeightStrategy(strategyAddr);
    }

    /*──────────────────── Strategy Registry ───────────────────*/

    /**
     * @notice Update the default weight strategy via governance.
     * @param id       Strategy interface id; must equal `IWeightStrategy(newAddr).id()`.
     * @param newAddr  New strategy contract address.
     *
     * @dev Reverts IdMismatch if id does not match the contract’s advertised id().
     *      Emits `DefaultStrategySet(id, newAddr)`.
     */
    function updateStrategy(bytes4 id, address newAddr) public onlyGovernance {
        if (id != IWeightStrategy(newAddr).id()) revert IdMismatch();
        
        defaultStrategy = IWeightStrategy(newAddr);
        emit DefaultStrategySet(id, newAddr);
    }

    /*──────────────────── Proposal hook (optional strategy override) ─────*/

    /**
     * @notice Disabled base `propose` (use extended version with timestamps).
     * @dev Always reverts to force using the timestamped variant.
     */
    function propose(
        address[] memory /*targets*/,
        uint256[] memory /*values*/,
        bytes[] memory /*calldatas*/,
        string  memory /*description*/
    )
        public
        pure
        override(GovernorUpgradeable)
        returns (uint256)
    {
        revert("Use extended propose with timestamps");
    }
    
    /**
     * @notice Create a proposal with explicit voting window.
     * @param proposer     The address recorded as proposer (also used for threshold check).
     * @param targets      Call targets.
     * @param values       ETH values per target.
     * @param calldatas    Encoded calldata per target.
     * @param description  Proposal description.
     * @param startTs      Voting start (unix). If 0, defaults to `block.timestamp`.
     * @param endTs        Voting end (unix). Must be > start and ≤ start + 60 days.
     * @return id          Newly created proposal id.
     *
     * @dev
     * - Requires a non-zero `defaultStrategy` (NoStrategy).
     * - If strategy `minThreshold()` > 0, verifies `getVotes(proposer, clock()-1)` meets threshold.
     * - Persists `Proposal` mirror and `{start,end}` to `_timeWindows` for custom `state()` logic.
     * - Emits standard Governor events internally.
     *
     * @custom:reverts InvalidTime   if endTs ≤ startTs or span > 60 days
     * @custom:reverts NoStrategy    if defaultStrategy is not set
     * @custom:reverts GovernorInsufficientProposerVotes if proposer lacks threshold
     */
    function propose(
        address proposer,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        uint64 startTs,
        uint64 endTs
    ) public returns (uint256 id) {
        if (startTs == 0) {
            startTs = uint64(block.timestamp);
        }
        if (endTs <= startTs || endTs - startTs > 60 days) revert InvalidTime();
        if (address(defaultStrategy) == address(0)) revert NoStrategy();

        // check proposal threshold
        uint256 votesThreshold = defaultStrategy.minThreshold();
        if (votesThreshold > 0) {
            uint256 proposerVotes = getVotes(proposer, clock() - 1);
            if (proposerVotes < votesThreshold) {
                revert GovernorInsufficientProposerVotes(proposer, proposerVotes, votesThreshold);
            }
        }
    
        id = super._propose(targets, values, calldatas, description, proposer);

        _timeWindows[id].start = startTs;
        _timeWindows[id].end = endTs;

        proposals[id] = Proposal({
            proposalId: id,
            proposer: proposer,
            targets: targets,
            values: values,
            calldatas: calldatas,
            start: startTs,
            end: endTs,
            description: description
        });
    }

    /**
     * @notice Create a “child” proposal (meta-governance) with a shared expected id.
     * @param sharedId    Expected id to be returned by `propose(...)`.
     * @param proposer    Recorded proposer (threshold checked).
     * @param targets     Call targets.
     * @param values      ETH values.
     * @param calldatas   Encoded calldata.
     * @param description Human-readable description.
     * @param startTs     Voting start (0 ⇒ now).
     * @param endTs       Voting end.
     * @return uint256    The proposal id (must equal `sharedId` or revert).
     *
     * @dev Sets `proposalOrigin[id] = Origin.Meta`. Only callable by `META_ROLE`.
     * @custom:reverts SharedIdMismatch if returned id != sharedId
     */
    function proposeChild(
        uint256 sharedId,
        address proposer,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        uint64 startTs,
        uint64 endTs
    ) external onlyRole(META_ROLE) returns (uint256) {
        uint256 id = propose(proposer, targets, values, calldatas, description, startTs, endTs);
        proposalOrigin[id] = Origin.Meta;
        if (id != sharedId) revert SharedIdMismatch();
        return id;
    }

    /**
     * @notice Return for/against tallies and total supply at snapshot.
     * @param id Proposal id.
     * @return yesVotes For votes.
     * @return noVotes  Against votes.
     * @return supply   Total voting supply at snapshot block.
     */
    function tally(uint256 id)
        external
        view
        returns (uint256 yesVotes, uint256 noVotes, uint256 supply)
    {
        (uint256 againstVotes, uint256 forVotes, ) = proposalVotes(id);
        return (forVotes, againstVotes, token().getPastTotalSupply(proposalSnapshot(id)));
    }

    /**
     * @notice Read back the extended proposal details.
     * @param id Proposal id.
     * @return proposer    Address of proposer.
     * @return targets     Targets array.
     * @return values      Values array.
     * @return calldatas   Calldata array.
     * @return start       Voting start timestamp.
     * @return end         Voting end timestamp.
     * @return description Human-readable description.
     */
    function getProposalDetails(uint256 id)
        external view
        returns (
            address proposer,
            address[] memory targets,
            uint256[] memory values,
            bytes[]   memory calldatas,
            uint64 start,
            uint64 end,
            string memory description
        )
    {
        Proposal storage p = proposals[id];
        return (p.proposer, p.targets, p.values, p.calldatas, p.start, p.end, p.description);
    }

    /*──────────────────── Weight override ─────────────────────*/

    /**
     * @notice Delegate weight calculation to `defaultStrategy.weight`.
     * @param voter        Address casting a vote.
     * @param blockNumber  Snapshot block.
     * @param              (unused) raw params.
     * @return uint256     Strategy-defined voting weight (bounded).
     *
     * @dev
     * - Performs `staticcall` to the strategy with `(voter, blockNumber, token(), "")`.
     * - Reverts `StrategyFailed()` on call failure; decodes `uint256` on success.
     * - Reverts `Overflow()` if weight > 1e36 to cap pathological strategies.
     */
    function _getVotes(
        address voter,
        uint256 blockNumber,
        bytes memory
    ) internal view override(GovernorUpgradeable, GovernorVotesUpgradeable) returns (uint256) {
        IWeightStrategy s = defaultStrategy;
        (bool ok, bytes memory ret) = address(s).staticcall(
            abi.encodeWithSelector(IWeightStrategy.weight.selector, voter, blockNumber, token(), "")
        );
        if (!ok) revert StrategyFailed();
        uint256 w = abi.decode(ret,(uint256));
        if (w>1e36) revert Overflow();
        return w;
    }

    /**
     * @notice Compute quorum using the strategy’s quorum function.
     * @param blockNumber Snapshot block.
     * @return uint256    Quorum amount required.
     */
    function quorum(uint256 blockNumber) public view
        override(GovernorUpgradeable)
        returns (uint256)
    {
        uint256 supply = token().getPastTotalSupply(blockNumber);
        return defaultStrategy.quorum(supply, blockNumber);
    }

    /**
     * @notice Start time accessor for proposal id.
     */
    function getStartTime(uint256 id)
        public view
        returns (uint256)
    {
        return _timeWindows[id].start;
    }

    /**
     * @notice End time accessor for proposal id.
     */
    function getEndTime(uint256 id)
        public view
        returns (uint256)
    {
        return _timeWindows[id].end;
    }

    /**
     * @notice State machine override to honor explicit {start,end} voting windows.
     * @param id Proposal id.
     * @return ProposalState Governor state value.
     *
     * @dev
     * - Before start: Pending
     * - Between start and end: Active
     * - After end: Succeeded/Defeated based on quorum & vote success; Queued if ETA set.
     */
    function state(uint256 id)
        public view override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (ProposalState)
    {
        ProposalState ps = super.state(id);
        if (ps != ProposalState.Active) return ps;

        uint64 nowTs = uint64(block.timestamp);

        if (nowTs < getStartTime(id))
            return ProposalState.Pending;

        if (nowTs < getEndTime(id))
            return ProposalState.Active;
        
        if (!_quorumReached(id) || !_voteSucceeded(id)) {
            return ProposalState.Defeated;
        } else if (proposalEta(id) == 0) {
            return ProposalState.Succeeded;
        } else {
            return ProposalState.Queued;
        }
    }

    /**
     * @notice Proposal threshold passthrough (from GovernorSettings).
     */
    function proposalThreshold()
        public view
        override(GovernorUpgradeable, GovernorSettingsUpgradeable)
        returns (uint256)
    { return super.proposalThreshold(); }

    /**
     * @notice Whether a proposal needs queuing (timelock).
     */
    function proposalNeedsQueuing(uint256 proposalId)
        public
        view
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (bool)
    {
        return super.proposalNeedsQueuing(proposalId);
    }

    /**
     * @dev Queue operations into the timelock (internal Governor plumbing).
     */
    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (uint48)
    {
        return super._queueOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    /**
     * @dev Execute operations from the timelock (internal Governor plumbing).
     */
    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
    {
        super._executeOperations(proposalId, targets, values, calldatas, descriptionHash);
    }

    /**
     * @dev Cancel proposal plumbing passthrough.
     */
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (uint256)
    { return super._cancel(targets, values, calldatas, descriptionHash); }

    /**
     * @dev Executor address resolution (timelock-aware).
     */
    function _executor()
        internal view
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (address)
    { return super._executor(); }

    /**
     * @notice Add or remove a trusted ERC-2771 forwarder.
     * @param forwarder Forwarder address.
     * @param trust     True to trust, false to revoke.
     *
     * @dev Only ADMIN_ROLE may call.
     */
    function updateForwarder(address forwarder, bool trust) external onlyRole(ADMIN_ROLE) {
        ERC2771ContextUpgradeable.updateTrustedForwarder(forwarder, trust);
    }

    /*──────────────────── Misc boilerplate ─────────────────────*/

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData()   internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /**
     * @notice Authorize UUPS upgrade; only Governance (via Governor).
     */
    function _authorizeUpgrade(address) internal override onlyGovernance {}

    /**
     * @notice ERC165 support aggregation across parents.
     */
    function supportsInterface(bytes4 iid) public view override(GovernorUpgradeable, AccessControlEnumerableUpgradeable) returns(bool){return super.supportsInterface(iid);}    

    /// @dev Storage gap for future variable additions.
    uint256[45] private __gap;
}

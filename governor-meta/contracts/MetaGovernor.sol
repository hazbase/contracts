// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//    https://hazbase.com

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorVotesQuorumFractionUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorCountingSimpleUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/extensions/GovernorTimelockControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/governance/TimelockControllerUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/governance/utils/IVotes.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/**
 *  @title MetaGovernor
 *
 *  @notice
 *  - Purpose: A meta-governor that orchestrates TWO child governors — an
 *    Economic governor (`econ`) and a Social governor (`soc`) — and finalizes
 *    proposals only when BOTH sides pass. It then schedules the payload via a
 *    timelock.
 *
 *  - How it works (high level):
 *      1) `propose(ProposalType, ...)` computes a shared proposal id (`hashProposal`)
 *         and calls `proposeChild` on BOTH child governors with the same id and the
 *         same call targets/values/calldatas/time window.
 *      2) Each child governor runs independently (with its own weights/quorum).
 *      3) Once both children reach `Succeeded`, anyone can call `finalize(id)` here.
 *         Finalize performs turnout and "super-majority" checks using combination
 *         rules per proposal type, and on success schedules the batch via the
 *         timelock controller.
 *
 *  - Combination rules (per `ProposalType`):
 *      * `baseFactors`: linear weights (basis points) to combine YES/NO from econ/soc.
 *      * `quorums`: minimum turnout (basis points of each child total supply) required.
 *      * `superRules`: (i) YES-share threshold in bp of YES/(YES+NO), (ii) turnout
 *        threshold in bp of (YES+NO) vs (supply_econ + supply_soc).
 *
 *  - Roles / Access:
 *      * Uses AccessControl for DEFAULT_ADMIN_ROLE (updating forwarders, etc.).
 *      * Upgrades gated by `onlyGovernance` (see `_authorizeUpgrade`).
 *
 *  - Security / Audit Notes:
 *      * Shared-id invariant: Both children MUST create the same id; we pass in the
 *        computed id to `proposeChild` on both. The child side should enforce id match.
 *      * Finalization requires BOTH children `Succeeded`. Additional checks (quorum,
 *        super-majority, combined turnout) guard against edge cases.
 *      * `finalize` schedules via Timelock (Batch). Execution is deferred until delay.
 *      * Meta uses ERC-2771 meta-tx context overrides. No custodied funds here.
 *      * Voting windows are enforced in the CHILD governors (meta does not vote/track).
 */

enum IProposalState {
    Pending,
    Active,
    Canceled,
    Defeated,
    Succeeded,
    Queued,
    Expired,
    Executed
}

/**
 * @dev Interface a child governor must expose so the meta layer can orchestrate it.
 */
interface IGovernorBasic {
    function META_ROLE() external view returns(bytes32);
    function DEFAULT_ADMIN_ROLE() external view returns(bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);
    function grantRole(bytes32 role, address account) external;
    function getVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @notice Child-side creation of a proposal with a shared id (provided by meta).
     * @param sharedId     Expected proposal id (must match child-side computed id).
     * @param proposer     Proposer address recorded in child.
     * @param targets      Call targets.
     * @param values       ETH values.
     * @param calldatas    Encoded calldata.
     * @param description  Human-readable description.
     * @param startTs      Voting start (unix).
     * @param endTs        Voting end (unix).
     * @return uint256     The child proposal id (should equal `sharedId`).
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
    ) external returns (uint256);

    /// @notice Child proposal state (mapped from OZ ProposalState).
    function state(uint256 id) external view returns (IProposalState);

    /// @notice For/against tallies and supply (at snapshot) from the child.
    function tally(uint256 id) external view returns (uint256 yesVotes, uint256 noVotes, uint256 supply);

    /// @notice Read back the original proposal details (used at schedule time).
    function getProposalDetails(uint256 id) external view
        returns (
            address proposer,
            address[] memory targets,
            uint256[] memory values,
            bytes[]   memory calldatas,
            uint64 start,
            uint64 end,
            string memory description
        );
}

/**
 * @title  MetaGovernor
 * @notice Reputation / stake hybrid meta-governor. It composes results from two child
 *         governors (economic & social) and schedules execution when combined rules pass.
 *
 *         Voting mechanics LIVE in the child governors; this contract coordinates them.
 */
contract MetaGovernor is
    GovernorVotesQuorumFractionUpgradeable,
    GovernorCountingSimpleUpgradeable,
    GovernorTimelockControlUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardUpgradeable
{
    /*────────────────────────── Types & Events ───────────────────────────*/

    /// @notice Proposal classification to select combination/quorum/super rules.
    enum ProposalType { Economic, Social, Mixed, Emergency }

    /// @notice Emitted after a successful `finalize`, with combined YES/NO.
    event Finalized(uint256 id, uint256 yes, uint256 no, address sender);

    /**
     * @dev Linear weights (in basis points) applied to each child tally:
     *      combined_yes = (yes_econ * eco + yes_soc * soc) / 10_000 (same for NO)
     */
    struct Factors { uint16 eco; uint16 soc; }

    /**
     * @dev Per-child turnout quorum in basis points vs each child’s total supply:
     *      (yes + no) * 10_000 >= supply * quorumBp
     */
    struct QuorumRule { uint16 eco; uint16 soc; }

    /**
     * @dev Super-majority + combined turnout thresholds:
     *      - yesBp: YES/(YES+NO) in bp (combined)
     *      - turnoutBp: (YES+NO) in bp vs (supply_econ + supply_soc)
     */
    struct SuperRule { uint16 yesBp; uint16 turnoutBp; }

    /// @notice Per-type linear combination factors.
    mapping(ProposalType => Factors)    public baseFactors;
    /// @notice Per-type child turnout requirements.
    mapping(ProposalType => QuorumRule) public quorums;
    /// @notice Per-type super-majority / combined turnout requirements.
    mapping(ProposalType => SuperRule)  public superRules;

    /// @dev Recorded proposal type by shared id.
    mapping(uint256 => ProposalType)    private _ptype;

    /// @notice Child governors (must implement IGovernorBasic).
    IGovernorBasic public econ;
    IGovernorBasic public soc;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    /*────────────────────────── Initializer ───────────────────────────────*/

    /**
     * @notice Initialize meta governor.
     * @param admin       DEFAULT_ADMIN_ROLE holder for meta (and typically child admin too).
     * @param name_       Governor name.
     * @param econAddr    Address of economic child governor (must implement IGovernorBasic).
     * @param socAddr     Address of social child governor (must implement IGovernorBasic).
     * @param timelock    Timelock controller for scheduling.
     * @param forwarders  Trusted ERC-2771 forwarders.
     *
     * @dev
     * - Grants DEFAULT_ADMIN_ROLE to `admin`.
     * - Optionally (commented) sanity-checks granting META_ROLE on children.
     * - Seeds default combination/quorum/super rules.
     */
    function initialize(
        address admin,
        string memory name_,
        address econAddr,
        address socAddr,
        TimelockControllerUpgradeable timelock,
        address[] calldata forwarders
    ) external initializer {
        require(econAddr != address(0) && socAddr != address(0), "zero addr");

        __Governor_init(name_);
        __GovernorTimelockControl_init(timelock);
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);

        _grantRole(DEFAULT_ADMIN_ROLE, admin);

        econ = IGovernorBasic(payable(econAddr));
        soc  = IGovernorBasic(payable(socAddr));

        // sanity: child governors must recognize this meta as META_ROLE
        /*
        bytes32 M = econ.META_ROLE();
        
        if (!econ.hasRole(M, address(this)) || !soc.hasRole(M, address(this))) {
            // Meta needs DEFAULT_ADMIN_ROLE on child for this one call
            require(econ.hasRole(econ.DEFAULT_ADMIN_ROLE(), admin) && soc.hasRole(soc.DEFAULT_ADMIN_ROLE(), admin), "child admin req");
            econ.grantRole(M, address(this));
            soc.grantRole(M, address(this));
        }
        */

        /* Default rules (basis points) */
        baseFactors[ProposalType.Economic]  = Factors(10000, 8000);   // econ=100%, soc=80%
        baseFactors[ProposalType.Social]    = Factors(8000, 10000);   // econ=80%,  soc=100%
        baseFactors[ProposalType.Mixed]     = Factors(9000, 9000);
        baseFactors[ProposalType.Emergency] = Factors(10000, 5000);

        quorums[ProposalType.Economic]  = QuorumRule(400, 200);       // 4% econ turnout, 2% social turnout
        quorums[ProposalType.Social]    = QuorumRule(200, 400);
        quorums[ProposalType.Mixed]     = QuorumRule(300, 300);
        quorums[ProposalType.Emergency] = QuorumRule(500, 300);

        superRules[ProposalType.Economic]  = SuperRule(6000, 5000);   // yes ≥60%, turnout ≥50% combined
        superRules[ProposalType.Social]    = SuperRule(6000, 4000);
        superRules[ProposalType.Mixed]     = SuperRule(6500, 5500);
        superRules[ProposalType.Emergency] = SuperRule(7500, 6000);
    }

    /*────────────────────────── Proposing ───────────────────────────────*/

    /**
     * @notice Disable the base OZ `propose` entry; meta requires typed propose below.
     * @dev Always reverts to force using the ProposalType version.
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
        revert("Use propose with ProposalType");
    }

    /**
     * @notice Create a proposal in BOTH child governors with the same shared id.
     * @param p         Proposal type to choose combination/quorum/super rules.
     * @param targets   Call targets.
     * @param values    ETH values.
     * @param calldatas Encoded calldata.
     * @param desc      Human-readable description.
     * @param startTs   Voting start timestamp (unix).
     * @param endTs     Voting end timestamp (unix).
     * @return id       Shared proposal id (hash of {targets, values, calldatas, descHash}).
     *
     * @dev
     * - Validates period and array length match.
     * - Writes `_ptype[id] = p`.
     * - Calls `proposeChild` on both children; they should enforce id match internally.
     */
    function propose(
        ProposalType p,
        address[] memory targets,
        uint256[] memory values,
        bytes[]   memory calldatas,
        string    memory desc,
        uint64    startTs,
        uint64    endTs
    ) external returns (uint256 id) {
        require(startTs < endTs && endTs > block.timestamp, "bad period");
        require(targets.length==values.length&&values.length==calldatas.length, "len mismatch");

        id = hashProposal(targets, values, calldatas, keccak256(bytes(desc)));
        _ptype[id] = p;
        econ.proposeChild(id, _msgSender(), targets, values, calldatas, desc, startTs, endTs);
        soc.proposeChild(id, _msgSender(), targets, values, calldatas, desc, startTs, endTs);
    }

    /**
     * @notice Convenience passthrough for reading child votes.
     * @param account   Address to query.
     * @param timepoint Snapshot timepoint/block as defined by child.
     * @return votes    Child-reported voting power.
     */
    function getEconVotes(address account, uint256 timepoint) external view returns (uint256 votes) {
        votes = econ.getVotes(account, timepoint);
    }

    /**
     * @notice Convenience passthrough for reading child votes.
     * @param account   Address to query.
     * @param timepoint Snapshot timepoint/block as defined by child.
     * @return votes    Child-reported voting power.
     */
    function getSocVotes(address account, uint256 timepoint) external view returns (uint256 votes) {
        votes = soc.getVotes(account, timepoint);
    }

    /*────────────────────────── Finalization ─────────────────────────────*/

    /**
     * @notice Finalize a proposal after BOTH children `Succeeded` and combined rules pass.
     * @param id Shared proposal id.
     *
     * @dev
     * - Requires econ.state(id) == Succeeded and soc.state(id) == Succeeded.
     * - Enforces per-type child turnout (`quorums`) vs each child supply.
     * - Combines YES/NO by `baseFactors[p]`.
     * - Enforces meta-level YES ratio (`superRules[p].yesBp`) and combined turnout
     *   vs (supply_e + supply_s) (`superRules[p].turnoutBp`).
     * - On success, schedules the batch via timelock with `getMinDelay()`.
     * - Emits `Finalized`.
     *
     * @custom:reverts econ not passed / soc not passed   if either child not Succeeded
     * @custom:reverts Eco quorum / Soc quorum            if child turnout too low
     * @custom:reverts no votes                           if YES+NO == 0 after combine
     * @custom:reverts yes threshold / turnout            if super rules not met
     */
    function finalize(uint256 id) external nonReentrant {
        require(econ.state(id) == IProposalState.Succeeded, "econ not passed");
        require(soc.state(id)  == IProposalState.Succeeded, "soc not passed");
        require(_ptype[id] <= ProposalType.Emergency, "unknown proposal");

        ProposalType p = _ptype[id];
        Factors memory f = baseFactors[p];
        QuorumRule memory q = quorums[p];
        SuperRule memory s = superRules[p];

        (uint256 yE,uint256 nE,uint256 supE) = econ.tally(id);
        (uint256 yS,uint256 nS,uint256 supS) = soc.tally(id);

        // Child-level turnout (in bp of each child's supply)
        require((yE+nE)*10000 >= supE*q.eco, "Eco quorum");
        require((yS+nS)*10000 >= supS*q.soc, "Soc quorum");

        // Linear combination of tallies
        uint256 yes = (yE * f.eco + yS * f.soc) / 10_000;
        uint256 no  = (nE * f.eco + nS * f.soc) / 10_000;
        uint256 sum = yes + no;

        require(sum>0, "no votes");
        require(yes * 1e4 >= sum * s.yesBp, "yes threshold");
        require(sum * 1e4 >= (supE+supS)*s.turnoutBp, "turnout");
        
        (
            ,
            address[] memory targets,
            uint256[] memory values,
            bytes[]   memory calldatas,
            ,
            ,
        ) = econ.getProposalDetails(id);

        // Schedule via the timelock (batch)
        bytes32 salt = keccak256(abi.encode(id));
        TimelockControllerUpgradeable tl = TimelockControllerUpgradeable(payable(_executor()));
        tl.scheduleBatch(targets, values, calldatas, 0, salt, tl.getMinDelay());

        emit Finalized(id, yes, no, _msgSender());
    }

    /*───────────────── Multiple-inheritance forwarders ───────────────────*/

    /**
     * @notice Voting delay (unused by meta; child windows control timing).
     * @return uint256 Minimal placeholder.
     */
    function votingDelay()
        public pure
        override(GovernorUpgradeable)
        returns (uint256)
    { return 1; }

    /**
     * @notice Voting period (unused by meta; child windows control timing).
     * @return uint256 Minimal placeholder.
     */
    function votingPeriod()
        public pure
        override(GovernorUpgradeable)
        returns (uint256)
    { return 1; }

    /**
     * @notice Proposal threshold passthrough.
     */
    function proposalThreshold()
        public view
        override(GovernorUpgradeable)
        returns (uint256)
    { return super.proposalThreshold(); }

    /**
     * @notice State passthrough to OZ Governor logic (meta does not override).
     */
    function state(uint256 id)
        public view override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (ProposalState)
    {
        return super.state(id);
    }

    /**
     * @notice Whether proposals require queuing (timelock).
     */
    function proposalNeedsQueuing(uint256 proposalId)
        public view
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (bool)
    { return super.proposalNeedsQueuing(proposalId); }

    /**
     * @dev Queue operations into timelock (internal Governor plumbing).
     */
    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[]   memory calldatas,
        bytes32   descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (uint48)
    { return super._queueOperations(proposalId, targets, values, calldatas, descriptionHash); }

    /**
     * @dev Execute operations from the timelock (internal Governor plumbing).
     */
    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[]   memory calldatas,
        bytes32   descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
    { super._executeOperations(proposalId, targets, values, calldatas, descriptionHash); }

    /**
     * @dev Cancel proposal plumbing passthrough.
     */
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[]   memory calldatas,
        bytes32   descriptionHash
    )
        internal
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (uint256)
    { return super._cancel(targets, values, calldatas, descriptionHash); }

    /**
     * @dev Timelock executor address resolution.
     */
    function _executor()
        internal view
        override(GovernorUpgradeable, GovernorTimelockControlUpgradeable)
        returns (address)
    { return super._executor(); }

    /**
     * @notice Add/remove trusted ERC-2771 forwarders (admin only).
     * @param forwarder Forwarder address.
     * @param trust     True to trust, false to revoke.
     */
    function updateForwarder(address forwarder, bool trust) external onlyRole(DEFAULT_ADMIN_ROLE) {
        ERC2771ContextUpgradeable.updateTrustedForwarder(forwarder, trust);
    }

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender()
        internal
        view
        override(ContextUpgradeable, ERC2771ContextUpgradeable)
        returns (address)
    { return ERC2771ContextUpgradeable._msgSender(); }

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData()
        internal
        view
        override(ContextUpgradeable, ERC2771ContextUpgradeable)
        returns (bytes calldata)
    { return ERC2771ContextUpgradeable._msgData(); }

    /*────────────────────────── UUPS gate ───────────────────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only Governance (via Governor).
     */
    function _authorizeUpgrade(address newImpl)
        internal
        override
        onlyGovernance
    {}

    /**
     * @notice ERC165 support aggregation across parents.
     */
    function supportsInterface(bytes4 iid) public view override(AccessControlUpgradeable, GovernorUpgradeable) returns (bool){
        return super.supportsInterface(iid);
    }

    /**
     * @dev Reserved storage to allow future variable additions (per OZ guidelines).
     */
    uint256[48] private __gap;
}

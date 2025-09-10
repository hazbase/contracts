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

import "@openzeppelin/contracts/utils/math/Math.sol";
import { IVotes } from "@openzeppelin/contracts/governance/utils/IVotes.sol";

/**
 *  @title Weight Strategies
 *
 *  @notice
 *  - Purpose: Pluggable voting weight strategies for `GenericGovernor`.
 *    Each strategy implements `IWeightStrategy` and defines:
 *      * `id()`         — compile-time identifier to sanity-check at registry updates.
 *      * `weight()`     — how a voter's voting weight is derived at a given block.
 *      * `quorum()`     — how required quorum is computed from (possibly transformed) supply.
 *      * `minThreshold()` — proposer threshold in *strategy weight* units.
 *
 *  - Implementations:
 *      1) OneTokenOneVote      : weight = raw ERC20Votes balance; quorum = pct of total raw supply.
 *      2) OnePersonOneVote     : weight ∈ {0,1} depending on non-zero balance; quorum = pct of total raw supply.
 *      3) QuadraticStake       : weight = sqrt(balance); quorum = pct of sqrt(total supply).
 *      4) ReputationAmplified  : weight = base + k * sqrt(balance); quorum = base + pct * sqrt(total supply).
 *
 *  - Security / Audit Notes:
 *      * All strategies read historical balances using `IVotes.getPastVotes(voter, blockNo)` which
 *        is snapshot-safe for governance.
 *      * `minThreshold` must be expressed in the same *weight unit* as `weight()` returns, which varies by strategy.
 *      * Identifiers (e.g., "1TOK"/"OPOV"/"QADR"/"REPA") are compile-time constants to prevent mismatched strategy swaps.
 *      * Inputs are not trusted—callers should validate strategy choice in Governor via `id()` equality.
 */
 
interface IWeightStrategy {
    /**
     * @notice Compile-time identifier of the strategy (e.g., "1TOK"/"QADR" etc.).
     * @return bytes4 Strategy id.
     */
    function id() external pure returns (bytes4);

    /**
     * @notice Compute the voting weight for `voter` at `blockNumber`.
     * @param voter        Address to evaluate.
     * @param blockNumber  Snapshot block (as used by Governor).
     * @param token        Governance token address (IVotes-compatible).
     * @param params       Optional extra params (unused in these implementations).
     * @return uint256     Weight value in the strategy's unit.
     */
    function weight(address voter, uint256 blockNumber, address token, bytes calldata params) external view returns (uint256);

    /**
     * @notice Compute quorum requirement from total supply (or transformed supply).
     * @param totalSupply  Total voting supply (raw) or input for transformation.
     * @param blockNo      Snapshot block (may be ignored).
     * @return uint256     Required quorum expressed in the same unit as `weight()`.
     */
    function quorum(uint256 totalSupply, uint256 blockNo) external view returns (uint256);

    /**
     * @notice Minimum proposer threshold in strategy weight units.
     * @return uint256 Threshold value (0 means no threshold).
     */
    function minThreshold() external view returns (uint256);
}

/*──────────────────────────────────────────────────────────────*/
/// OneTokenOneVote  – raw ERC20 balance, 1 token = 1 vote
/**
 * @title OneTokenOneVote
 * @notice Voting weight equals raw ERC20Votes balance at snapshot; quorum is % of total raw supply.
 * @dev Threshold is expressed directly in raw tokens (same unit as weight).
 */
contract OneTokenOneVote is IWeightStrategy {
    using Math for uint256;

    /// @dev Strategy id: "1TOK" (0x31 0x54 0x4f 0x4b).
    bytes4 internal constant _ID = 0x31544f4b; // "1TOK"

    /// @notice Quorum percentage of total raw supply (e.g., 4 means 4%).
    uint16 public immutable quorumPct;

    /// @notice Proposer threshold in raw token units (same as weight units).
    uint256 public immutable threshold;

    /**
     * @param _pct         Quorum numerator (% of total raw supply, 1..100).
     * @param tokenThresh  Raw token amount required to create a proposal.
     */
    constructor(uint16 _pct, uint256 tokenThresh) {
        require(_pct > 0 && _pct <= 100, "pct");
        quorumPct = _pct;
        threshold = tokenThresh; // 1 token = 1 weight ⇒ no conversion
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function id() external pure override returns(bytes4){ return _ID; }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Reads `IVotes(token).getPastVotes(voter, blockNo)` (raw).
     */
    function weight(address voter,uint256 blockNo,address token, bytes calldata) external view override returns(uint256){
        return IVotes(token).getPastVotes(voter,blockNo);
    }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Quorum is pct of total raw supply: (total * pct) / 100.
     */
    function quorum(uint256 total,uint256) external view override returns(uint256){
        return (total * quorumPct) / 100;
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function minThreshold() external view override returns(uint256){ return threshold; }
}

/*──────────────────────────────────────────────────────────────*/
/// OnePersonOneVote – any non-zero balance counts as 1 vote
/**
 * @title OnePersonOneVote
 * @notice Voting weight is 1 if holder has non-zero balance at snapshot, else 0; quorum is % of total raw supply.
 * @dev Threshold is expressed in "holder-votes" (each holder contributes at most 1).
 */
contract OnePersonOneVote is IWeightStrategy {
    /// @dev Strategy id: "OPOV".
    bytes4 internal constant _ID = 0x4f504f56; // "OPOV"

    /// @notice Quorum percentage of total raw supply.
    uint16 public immutable quorumPct;

    /// @notice Proposer threshold in holder-vote units (1 per eligible holder).
    uint256 public immutable threshold;

    /**
     * @param _pct          Quorum numerator (% of total raw supply, 1..100).
     * @param holderThresh  Number of unique voters required to propose (in holder-votes).
     */
    constructor(uint16 _pct, uint256 holderThresh){
        require(_pct>0 && _pct<=100, "pct");
        quorumPct = _pct;
        threshold = holderThresh; // 1 holder = 1 weight ⇒ no conversion
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function id() external pure override returns(bytes4){ return _ID; }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Returns 1 iff past votes > 0 at `blockNo`, else 0.
     */
    function weight(address voter,uint256 blockNo, address token, bytes calldata) external view override returns(uint256){
        return IVotes(token).getPastVotes(voter,blockNo) > 0 ? 1 : 0;
    }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Quorum is pct of total raw supply: (total * pct) / 100.
     */
    function quorum(uint256 total,uint256) external view override returns(uint256){
        return (total * quorumPct) / 100;
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function minThreshold() external view override returns(uint256){ return threshold; }
}

/*──────────────────────────────────────────────────────────────*/
/// QuadraticStake – weight = sqrt(balance)
/**
 * @title QuadraticStake
 * @notice Voting weight is √(raw balance); quorum is pct of √(total supply).
 * @dev Threshold is expressed in √token units (converted from a raw token threshold in ctor).
 */
contract QuadraticStake is IWeightStrategy {
    using Math for uint256;

    /// @dev Strategy id: "QADR".
    bytes4 internal constant _ID = 0x51414452; // "QADR"

    /// @notice Quorum percentage applied to sqrt(total supply).
    uint16 public immutable quorumPct;

    /// @notice Proposer threshold in √token units (i.e., same unit as `weight()`).
    uint256 public immutable threshold;

    /**
     * @param _pct            Quorum numerator (% of sqrt(total), 1..100).
     * @param tokenThreshRaw  Raw token amount required to propose (converted to √tokens).
     */
    constructor(uint16 _pct, uint256 tokenThreshRaw){
        require(_pct>0 && _pct<=100, "pct");
        quorumPct = _pct;
        threshold = tokenThreshRaw.sqrt(); // convert to weight-unit (√tokens)
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function id() external pure override returns(bytes4){ return _ID; }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Computes √(pastVotes).
     */
    function weight(address voter,uint256 blockNo,address token,bytes calldata) external view override returns(uint256){
        uint256 bal = IVotes(token).getPastVotes(voter,blockNo);
        return bal.sqrt();
    }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Quorum is pct of √(total): (sqrt(total) * pct) / 100.
     */
    function quorum(uint256 total,uint256) external view override returns(uint256){
        return (total.sqrt() * quorumPct) / 100;
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function minThreshold() external view override returns(uint256){ return threshold; }
}

/*──────────────────────────────────────────────────────────────*/
/// ReputationAmplified – weight = base + k*sqrt(balance)
/**
 * @title ReputationAmplified
 * @notice Voting weight is `base + k * √(balance)`; quorum is `base + pct * √(total supply)`.
 * @dev Threshold is expressed in *weight* units: `threshold = base + k * √(tokenThreshRaw)`.
 */
contract ReputationAmplified is IWeightStrategy {
    using Math for uint256;

    /// @dev Strategy id: "REPA".
    bytes4 internal constant _ID = 0x52455041; // "REPA"

    /// @notice Baseline reputation component added to every eligible voter.
    uint64 public immutable base;

    /// @notice Amplification multiplier for √(balance).
    uint64 public immutable k;

    /// @notice Quorum percentage applied to √(total supply), added to `base`.
    uint16 public immutable quorumPct;

    /// @notice Proposer threshold in *weight* units (base + k*√tokens).
    uint256 public immutable threshold;

    /**
     * @param _base           Baseline reputation added to weight/quorum.
     * @param _k              Multiplier for √(balance).
     * @param _pct            Quorum numerator (% of √total, 1..100).
     * @param tokenThreshRaw  Raw token amount used to derive proposer threshold:
     *                        `threshold = base + k * √(tokenThreshRaw)`.
     */
    constructor(uint64 _base,uint64 _k,uint16 _pct,uint256 tokenThreshRaw){
        require(_pct>0 && _pct<=100, "pct");
        base=_base; k=_k; quorumPct=_pct;
        threshold = uint256(base) + uint256(k) * tokenThreshRaw.sqrt();
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function id() external pure override returns(bytes4){ return _ID; }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Returns 0 if balance is zero; else `base + k * √(balance)`.
     */
    function weight(address voter,uint256 blockNo,address token,bytes calldata) external view override returns(uint256){
        uint256 bal = IVotes(token).getPastVotes(voter,blockNo);
        if(bal==0) return 0;
        return uint256(base) + uint256(k)*bal.sqrt();
    }

    /**
     * @inheritdoc IWeightStrategy
     * @dev Quorum = `base + pct * √(total) / 100`.
     */
    function quorum(uint256 total,uint256) external view override returns(uint256){
        return uint256(base) + (total.sqrt() * quorumPct) / 100;
    }

    /**
     * @inheritdoc IWeightStrategy
     */
    function minThreshold() external view override returns(uint256){ return threshold; }
}

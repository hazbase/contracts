// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//    https://hazbase.com

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

import "./CircuitBreakerAMM.sol";

/**
 *  @title AMMFactory
 *
 *  @notice
 *  - Purpose: Minimal factory to deploy CircuitBreakerAMM pools as EIP-1167 minimal clones
 *             with deterministic addresses (CREATE2), apply shared default parameters, and
 *             registry mapping from (token0, token1) to pool address.
 *  - Governance & Access:
 *      * AccessControl-based roles: DEFAULT_ADMIN_ROLE and GOVERNOR_ROLE.
 *      * `governor` address is granted admin & governor roles in the constructor.
 *      * Only GOVERNOR_ROLE can create pools and update defaults; `onlyGovernor` can upgrade implementation.
 *  - Implementation Upgrades:
 *      * `upgradeImplementation` changes the implementation used for future clones only.
 *        Existing pools are unaffected (they keep pointing to the old logic code deployed at clone time).
 *  - Determinism & Registry:
 *      * Token ordering (`_sortTokens`) ensures (token0 < token1).
 *      * CREATE2 salt is `keccak256(token0, token1)` so `poolOf[key]` and clone address remain deterministic.
 *  - Fees & Limits:
 *      * `Defaults` stores factory-level default params passed to each new pool’s `initialize`.
 *        Individual pools may later tune their parameters internally (subject to their own ACL).
 *  - Security / Audit Notes:
 *      * The factory trusts `implementation` to expose a compatible `initialize` interface.
 *      * Front-running: `createPool` is restricted to GOVERNOR_ROLE; public users cannot race to create pairs.
 *      * Reverts: sanity checks include non-identical tokens and uniqueness of pair.
 *      * No UUPS/upgrade hooks here: the factory itself is not upgradeable; therefore no `_authorizeUpgrade`.
 *      * No ERC-2771 meta-tx; hence no `_msgSender` override in this file (keep comment parity across files).
 *
 *  Related:
 *  - CircuitBreakerAMM: must implement `initialize(address,address,address,uint32,uint32,uint32,uint32,uint32,uint32,address)`
 *  - Splitter (fee router): shared address passed to each pool.
 */

contract AMMFactory is AccessControl {
    using Clones for address;

    /// @notice Role id for governor-level operations (create pools, set defaults).
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");

    /// @notice Governor EOA/contract; also granted DEFAULT_ADMIN_ROLE and GOVERNOR_ROLE in constructor.
    address public governor;

    /// @notice Base implementation (logic) for EIP-1167 minimal clones of CircuitBreakerAMM.
    address public implementation; // CircuitBreakerAMM logic

    /// @notice Shared fee router (splitter) passed to each new pool at initialization.
    address public immutable splitter;       // shared fee router

    /**
     * @notice Default parameters applied to every new pool at `initialize`.
     * @dev Units are in basis points (bps) for fee-related fields; interpretation is up to the pool.
     * - baseFeeBps:   Base swap fee (in bps).
     * - feeAlphaBps:  Fee EMA/decay factor (in bps) for dynamic fee (if used by AMM).
     * - lvl1Bps..lvl3Bps: Tiered fee/penalty levels (in bps) used by CircuitBreaker.
     * - maxTxBps:     Max transaction size as a fraction of liquidity (in bps).
     */
    struct Defaults {
        uint32 baseFeeBps;
        uint32 feeAlphaBps;
        uint32 lvl1Bps;
        uint32 lvl2Bps;
        uint32 lvl3Bps;
        uint32 maxTxBps;
    }

    /// @notice Current default parameters used for newly created pools.
    Defaults public defaults;

    /// @notice Mapping from ordered token pair => pool address. Key is keccak256(token0, token1).
    mapping(bytes32 => address) public poolOf;

    /// @notice Emitted after a new pool clone is created and initialized.
    event PoolCreated(address indexed token0, address indexed token1, address pool);

    /// @notice Emitted when the base implementation is upgraded (affects future pools only).
    event ImplementationUpgraded(address oldImpl, address newImpl);

    /// @notice Emitted when factory defaults are updated.
    event DefaultsUpdated();

    /**
     * @notice Deploy the factory with initial implementation, splitter, defaults and governor.
     * @param _impl      Address of CircuitBreakerAMM logic contract (must be deployed with code).
     * @param _splitter  Shared fee router to pass to each pool.
     * @param _defaults  Default parameter set applied on pool initialization.
     * @param _governor  Governor address to receive admin & governor roles.
     *
     * @dev
     * - Grants DEFAULT_ADMIN_ROLE and GOVERNOR_ROLE to `governor`.
     * - Reverts if `_impl` has no code (sanity).
     */
    constructor(
        address _impl,
        address _splitter,
        Defaults memory _defaults,
        address _governor
    ) {
        require(_impl.code.length > 0, "impl-0");
        implementation = _impl;
        splitter       = _splitter;
        defaults       = _defaults;
        governor       = _governor;

        _grantRole(DEFAULT_ADMIN_ROLE, governor);
        _grantRole(GOVERNOR_ROLE, governor);
    }

    /**
     * @notice Restrict function to the explicit `governor` address.
     * @dev This is in addition to role-based checks elsewhere; used only for `upgradeImplementation`.
     */
    modifier onlyGovernor() {
        require(msg.sender == governor, "not-governor");
        _;
    }

    /* ------------------------------------------------------------------ */
    /*                       Pool management                               */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Create a new AMM pool for tokenA/tokenB if it does not already exist.
     * @param tokenA  ERC20 token address A.
     * @param tokenB  ERC20 token address B.
     * @return pool   Address of the newly created pool clone.
     *
     * @dev
     * - Access: only GOVERNOR_ROLE.
     * - Ordering: `_sortTokens` enforces (token0 < token1). Reverts if tokens are identical.
     * - Uniqueness: Uses `keccak256(token0, token1)` as key; reverts if a pool already exists.
     * - Deployment: `implementation.cloneDeterministic(salt)` with salt=key for CREATE2 determinism.
     * - Initialization: Calls `CircuitBreakerAMM(pool).initialize(...)` with factory defaults and
     *   `msg.sender` as the pool’s governor/owner (as per AMM’s own access model).
     * - Emits: `PoolCreated(token0, token1, pool)`.
     *
     * @custom:reverts identical     when tokenA == tokenB
     * @custom:reverts pool exists   when a pool for (token0, token1) already exists
     */
    function createPool(address tokenA, address tokenB) external onlyRole(GOVERNOR_ROLE) returns (address pool) {
        require(tokenA != tokenB, "identical");
        (address t0, address t1) = _sortTokens(tokenA, tokenB);
        bytes32 key = keccak256(abi.encodePacked(t0, t1));
        require(poolOf[key] == address(0), "pool exists");

        bytes32 salt = key; // deterministic
        pool = implementation.cloneDeterministic(salt);

        CircuitBreakerAMM(pool).initialize(
            t0,
            t1,
            splitter,
            defaults.baseFeeBps,
            defaults.feeAlphaBps,
            defaults.lvl1Bps,
            defaults.lvl2Bps,
            defaults.lvl3Bps,
            defaults.maxTxBps,
            msg.sender
        );
        poolOf[key] = pool;
        emit PoolCreated(t0, t1, pool);
    }

    /**
     * @notice Lookup an existing pool address for a pair.
     * @param tokenA  ERC20 token address A.
     * @param tokenB  ERC20 token address B.
     * @return address Pool address or address(0) if none.
     *
     * @dev Sorts tokens internally to match registry keying.
     */
    function getPool(address tokenA, address tokenB) external view returns (address) {
        (address t0, address t1) = _sortTokens(tokenA, tokenB);
        return poolOf[keccak256(abi.encodePacked(t0, t1))];
    }

    /* ------------------------------------------------------------------ */
    /*                       Defaults adjustment                           */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Update the factory defaults used for future pools.
     * @param d  New Defaults struct to set.
     *
     * @dev Access: only GOVERNOR_ROLE. Emits `DefaultsUpdated`.
     *      Does not alter parameters of existing pools (they keep their own config).
     */
    function setDefaults(Defaults calldata d) external onlyRole(GOVERNOR_ROLE) {
        defaults = d;
        emit DefaultsUpdated();
    }

    /* ------------------------------------------------------------------ */
    /*                       internal helpers                              */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Sort two token addresses to establish canonical (token0, token1) ordering.
     * @param a  First token address.
     * @param b  Second token address.
     * @return token0  The lower address.
     * @return token1  The higher address.
     *
     * @dev Pure function; ties are rejected by caller prior to use.
     */
    function _sortTokens(address a, address b) private pure returns (address, address) {
        return a < b ? (a, b) : (b, a);
    }

    /**
     * @notice Upgrade the base implementation for future clones.
     * @param newImpl  Address of the new CircuitBreakerAMM logic (must contain code).
     *
     * @dev Access: `onlyGovernor` (explicit governor address). Emits `ImplementationUpgraded`.
     *      Does NOT affect already deployed pools.
     * @custom:reverts impl0 when `newImpl` has no code
     */
    function upgradeImplementation(address newImpl) external onlyGovernor {
        require(newImpl.code.length > 0, "impl0");
        address old = implementation;
        implementation = newImpl;
        emit ImplementationUpgraded(old, newImpl);
    }
}

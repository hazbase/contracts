// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______    
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\   
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\   
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\ 
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/                                                                         
//
//    https://hazbase.com

import "@openzeppelin/contracts/proxy/Clones.sol";
import "./SmartAccount.sol";

/**
 * @title AccountFactory
 *
 * @notice
 * - Purpose: Deterministic factory for minimal proxy **SmartAccount** instances
 *   (EIP-1167 clones), keyed by `(owner, salt)` and initialized with a fixed
 *   `entryPoint` and `safe` configuration.
 *
 * - Features:
 *   * Deterministic address via `Clones.cloneDeterministic` and `predictDeterministicAddress`.
 *   * One-time key usage enforced on `(owner, salt)` to prevent duplicate deployments.
 *   * Upgradable **implementation** for future clones; existing clones are unaffected.
 *   * Upgrade authority restricted to the `safe` address (e.g., a Gnosis Safe).
 *
 * @dev SECURITY / AUDIT NOTES
 * - `implementation` MUST point to a deployed SmartAccount logic contract. The code-size
 *   checks (`impl.code.length > 0`) defend against zero-code addresses.
 * - The factory writes no business logic to clones besides calling `initialize` exactly once.
 * - The factory itself is not upgradeable; only its implementation reference can be changed.
 */
contract AccountFactory {
    /// @notice Current SmartAccount logic used for new clones.
    address public implementation;

    /// @notice Guard against reusing the same `(owner, salt)` tuple.
    mapping(bytes32 => bool) public usedKey;

    /// @notice Entrypoint address passed to each SmartAccount on initialization.
    address public immutable entryPoint;

    /// @notice Authorized address allowed to upgrade the `implementation` (commonly a multisig safe).
    address public safe;

    /*────────────────────────── Events ─────────────────────────*/

    /// @notice Emitted after a new SmartAccount clone is created and initialized.
    /// @param account  Deployed clone address.
    /// @param owner    Owner that the account was initialized with.
    /// @param salt     User-provided salt used to derive the deterministic address.
    event AccountCreated(address account, address owner, uint256 salt);

    /// @notice Emitted when the factory's implementation reference is upgraded.
    /// @param oldImpl  Previous logic address.
    /// @param newImpl  New logic address to be used for future clones.
    event ImplementationUpgraded(address oldImpl, address newImpl);

    /*────────────────────────── Modifiers ─────────────────────*/

    /**
     * @notice Restrict function to the `safe` address.
     * @dev Used to guard `upgradeImplementation`.
     *
     * @custom:reverts not-safe if `msg.sender != safe`
     */
    modifier onlySafe() {
        require(msg.sender == safe, "not-safe");
        _;
    }

    /*────────────────────────── Constructor ───────────────────*/

    /**
     * @notice Deploy the factory with initial logic and configuration.
     * @param _impl        SmartAccount logic (must contain code).
     * @param _entryPoint  Entrypoint that SmartAccounts will reference.
     * @param _safe        Address authorized to upgrade `implementation`.
     *
     * @dev
     * - Sets `implementation`, `entryPoint` (immutable), and `safe`.
     *
     * @custom:reverts impl-0 if `_impl` has no code (not a contract)
     */
    constructor(address _impl, address _entryPoint, address _safe) {
        require(_impl.code.length > 0, "impl-0");
        implementation = _impl;
        entryPoint = _entryPoint;
        safe = _safe;
    }

    /*────────────────────────── Internals ─────────────────────*/

    /**
     * @notice Derive a unique key for `(owner, salt)` used for both determinism and replay-guard.
     * @param owner  Future SmartAccount owner.
     * @param salt   User-provided salt (any uint256).
     * @return bytes32 Hash key = `keccak256(abi.encode(owner, salt))`.
     */
    function _key(address owner, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, salt));
    }

    /*────────────────────────── Externals ─────────────────────*/

    /**
     * @notice Create a new SmartAccount clone deterministically.
     * @param owner  Owner to initialize the SmartAccount with (must be non-zero).
     * @param salt   Arbitrary user salt; paired with `owner` to derive the address.
     * @return account  Address of the deployed SmartAccount clone.
     *
     * @dev
     * - Computes `key = keccak256(owner, salt)`, enforces single use (`usedKey`).
     * - Deploys an EIP-1167 minimal proxy via `Clones.cloneDeterministic(implementation, key)`.
     * - Calls `SmartAccount.initialize(owner, entryPoint, safe)` on the clone.
     * - Emits `AccountCreated`.
     *
     * @custom:reverts owner0     if `owner == address(0)`
     * @custom:reverts salt-used  if `(owner, salt)` has been used before
     */
    function createAccount(address owner, uint256 salt) external returns (address account) {
        require(owner != address(0), "owner0");
        bytes32 key = _key(owner, salt);
        require(!usedKey[key], "salt-used");

        account = Clones.cloneDeterministic(implementation, key);
        usedKey[key] = true;

        SmartAccount(payable(account)).initialize(owner, entryPoint, safe);
        emit AccountCreated(account, owner, salt);
    }

    /**
     * @notice Predict the deterministic address for a `(owner, salt)` pair.
     * @param owner  Intended SmartAccount owner.
     * @param salt   Arbitrary user salt.
     * @return address Predicted clone address if created with the current `implementation`.
     *
     * @dev Pure view over the CREATE2 address space for `implementation` and this factory.
     *      Does **not** reserve or mark the key as used.
     */
    function predictAddress(address owner, uint256 salt) external view returns (address) {
        bytes32 key = _key(owner, salt);
        return Clones.predictDeterministicAddress(implementation, key, address(this));
    }

    /*────────────────────────── Implementation Upgrade ────────*/

    /**
     * @notice Update the SmartAccount logic used for **future** clones.
     * @param newImpl Address of the new logic contract (must contain code).
     *
     * @dev Only callable by `safe`. Existing accounts are unaffected.
     *
     * @custom:reverts impl0 if `newImpl` has no code
     */
    function upgradeImplementation(address newImpl) external onlySafe {
        require(newImpl.code.length > 0, "impl0");
        address old = implementation;
        implementation = newImpl;
        emit ImplementationUpgraded(old, newImpl);
    }
}

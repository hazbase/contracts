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

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

interface IVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata publicSignals
    ) external view returns (bool);
}

/**
 * @title Whitelist
 *
 * @notice
 * - Purpose: Upgradeable **KYC / allowlist** registry with two trust levels:
 *   * `Basic` — set directly by admins (batch or single),
 *   * `ZK`    — added by a verifier after a valid zk-proof against a Merkle root.
 *   Users can be queried with `isWhitelisted()` and `kycLevel()`. Downgrading from
 *   `ZK` to `Basic` is disallowed.
 *
 * - Features:
 *   * Role model: `ADMIN_ROLE` (manage entries & verifier), `VERIFIER_ROLE` (update root, add ZK).
 *   * Merkle **root rotation** controlled by `VERIFIER_ROLE`.
 *   * **Nullifier** registry to prevent reuse of the same zk-proof (anti-replay).
 *   * ERC-2771 meta-transactions, Pausable, and UUPS upgradeable.
 *
 * @dev SECURITY / AUDIT NOTES
 * - `addWithVerify` enforces binding of proof to `{currentRoot, to}` and nullifier uniqueness.
 * - Batch updates cap at 5000 entries per call to avoid gas grief.
 * - Owner (separate from RolesCommon) kept for historical compatibility; roles govern behavior.
 */

contract Whitelist is
    Initializable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable,
    PausableUpgradeable
{
    /*────────────────── Roles ──────────────────*/

    /// @notice Addresses allowed to rotate Merkle root and invoke zk additions.
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    /*────────────────── Enums / Storage ──────────────────*/

    /// @notice KYC trust level.
    enum KYCLevel { None, Basic, ZK }

    /// @notice ZK verifier contract (Groth16-style).
    IVerifier public verifier;

    /// @notice Current Merkle root binding zk proofs to a cohort.
    bytes32 public currentRoot;

    /// @dev Per-user KYC level.
    mapping(address => KYCLevel) private _kycLevel;

    /// @dev Used nullifier hashes to prevent proof replay.
    mapping(bytes32 => bool) private _usedNullifier;

    /// @notice Legacy owner field (roles govern behavior).
    address public owner;

    /*────────────────── Events ──────────────────*/

    event WhitelistUpdated(address indexed user, KYCLevel level);
    event BatchWhitelistUpdated(uint256 count, KYCLevel level);
    event RootUpdated(bytes32 newRoot);
    event VerifierSet(address verifier);
    event ZKAdded(address indexed user);

    /**
     * @notice Disable initializers for the implementation (UUPS pattern).
     */
    constructor() { _disableInitializers(); }

    /*────────────────── Initializer ──────────────────*/

    /**
     * @notice Initialize the whitelist registry.
     * @param admin        Admin address (granted roles via RolesCommon).
     * @param initialRoot  Initial Merkle root accepted for zk proofs.
     * @param _verifier    ZK verifier contract address.
     * @param forwarders   Trusted ERC-2771 forwarders (meta-tx).
     *
     * @dev Grants `VERIFIER_ROLE` to `admin` by default. Emits `VerifierSet`.
     */
    function initialize(address admin, bytes32 initialRoot, address _verifier, address[] calldata forwarders) external initializer {
        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);
        __Pausable_init();

        owner = admin;

        _grantRole(VERIFIER_ROLE, admin);

        currentRoot = initialRoot;
        verifier = IVerifier(_verifier);
        emit VerifierSet(_verifier);
    }

    /*────────────────── Admin: Basic level ──────────────────*/

    /**
     * @notice Set `user` to `Basic` level.
     * @param user Address to mark as KYC Basic.
     *
     * @dev Only ADMIN_ROLE. Emits `WhitelistUpdated`.
     */
    function add(address user) external onlyRole(ADMIN_ROLE) { _set(user, KYCLevel.Basic); }

    /**
     * @notice Remove `user` from whitelist (level → None).
     * @param user Address to remove.
     *
     * @dev Only ADMIN_ROLE. Emits `WhitelistUpdated`.
     */
    function remove(address user) external onlyRole(ADMIN_ROLE) { _set(user, KYCLevel.None);  }

    /**
     * @notice Batch set users to `Basic`.
     * @param u Array of user addresses.
     *
     * @dev Only ADMIN_ROLE. Emits `BatchWhitelistUpdated`.
     *
     * @custom:reverts too many if `u.length > 5000`
     */
    function addBatch(address[] calldata u) external onlyRole(ADMIN_ROLE) { _batch(u, KYCLevel.Basic);  }

    /**
     * @notice Batch remove users (set to `None`).
     * @param u Array of user addresses.
     *
     * @dev Only ADMIN_ROLE. Emits `BatchWhitelistUpdated`.
     *
     * @custom:reverts too many if `u.length > 5000`
     */
    function removeBatch(address[] calldata u) external onlyRole(ADMIN_ROLE) { _batch(u, KYCLevel.None);   }

    /**
     * @notice Rotate the Merkle root used for ZK verification.
     * @param newRoot New root.
     *
     * @dev Only VERIFIER_ROLE. Emits `RootUpdated`.
     */
    function setRoot(bytes32 newRoot) external whenNotPaused onlyRole(VERIFIER_ROLE) {
        currentRoot = newRoot;
        emit RootUpdated(newRoot);
    }

    /**
     * @notice Update verifier contract address.
     * @param v Verifier address (non-zero).
     *
     * @dev Only ADMIN_ROLE. Emits `VerifierSet`.
     * @custom:reverts zero addr if `v == 0`
     */
    function setVerifier(address v) external whenNotPaused onlyRole(ADMIN_ROLE) {
        require(v != address(0), "zero addr");
        verifier = IVerifier(v);
        emit VerifierSet(v);
    }

    /*────────────────── Verifier: ZK level ──────────────────*/

    /**
     * @notice Add `to` to whitelist at `ZK` level after verifying Groth16 proof.
     * @param to          Address to mark as ZK level.
     * @param a,b,c       Proof elements.
     * @param pubSignals  Public inputs expected by the circuit:
     *                    - [0] mode (0 == KYC)
     *                    - [1] Merkle root
     *                    - [2] nullifier (uniqueness)
     *                    - [3] address binding (uint160(to))
     * @dev
     * - Requires `verifier` set and `currentRoot != 0`.
     * - Checks mode/root/address equality and unused nullifier.
     * - Calls external `verifyProof`; on success, nullifier is burned and `_set(to, ZK)` is applied.
     * - Emits `ZKAdded`.
     *
     * @custom:reverts verifier !set    if verifier is unset
     * @custom:reverts root undefined   if `currentRoot == 0`
     * @custom:reverts mode != KYC      if pubSignals[0] != 0
     * @custom:reverts root mismatch    if pubSignals[1] != currentRoot
     * @custom:reverts addr mismatch    if pubSignals[3] != to
     * @custom:reverts nullifier used   if nullifier already consumed
     * @custom:reverts invalid proof    if verifier rejects
     */
    function addWithVerify(
        address to,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[6] calldata pubSignals
    ) external whenNotPaused onlyRole(VERIFIER_ROLE) {
        require(address(verifier) != address(0), "verifier !set");
        require(currentRoot != 0, "root undefined");

        require(pubSignals[0] == 0, "mode != KYC");   // optional
        require(pubSignals[1] == uint256(currentRoot), "root mismatch");
        require(pubSignals[3] == uint256(uint160(to)), "addr mismatch");

        bytes32 nullifierHash = bytes32(pubSignals[2]);
        require(!_usedNullifier[nullifierHash], "nullifier used");

        bool ok = verifier.verifyProof(a, b, c, pubSignals);
        require(ok, "invalid proof");

        _usedNullifier[nullifierHash] = true;
        _set(to, KYCLevel.ZK);
        emit ZKAdded(to);
    }

    /*────────────────── Public views ──────────────────*/

    /**
     * @notice True if `user` is whitelisted at any level.
     */
    function isWhitelisted(address user) external view returns (bool) {
        return _kycLevel[user] != KYCLevel.None;
    }

    /**
     * @notice Return the KYC level for `user`.
     */
    function kycLevel(address user) external view returns (KYCLevel) {
        return _kycLevel[user];
    }

    /**
     * @notice Check whether a `nullifier` has already been used.
     */
    function usedNullifier(bytes32 nf) external view returns (bool) {
        return _usedNullifier[nf];
    }

    /*────────────────── Internal helpers ──────────────────*/

    /**
     * @notice Set user level with downgrade guard.
     * @param u  User address.
     * @param lv Target KYC level.
     *
     * @dev Reverts if attempting to downgrade from ZK to Basic. Emits `WhitelistUpdated` on change.
     * @custom:reverts no op                 if new level equals current level
     * @custom:reverts downgrade not allowed if lv==Basic and current==ZK
     */
    function _set(address u, KYCLevel lv) internal {
        require(_kycLevel[u] != lv, "no op");
        if (lv == KYCLevel.Basic && _kycLevel[u] == KYCLevel.ZK) revert("downgrade not allowed");
        _kycLevel[u] = lv;
        emit WhitelistUpdated(u, lv);
    }

    /**
     * @notice Batch set levels with 5000 cap and downgrade guard.
     * @param arr Addresses to update.
     * @param lv  Level to set.
     *
     * @dev Emits `BatchWhitelistUpdated`.
     * @custom:reverts too many if `arr.length > 5000`
     */
    function _batch(address[] calldata arr, KYCLevel lv) internal {
        require(arr.length <= 5000, "too many");
        for (uint256 i; i < arr.length; ++i) {
            address u = arr[i];
            if (_kycLevel[u] != lv) {
                if (lv == KYCLevel.Basic && _kycLevel[u] == KYCLevel.ZK) {
                    revert("downgrade not allowed");
                }
                _kycLevel[u] = lv;
            }
        }
        emit BatchWhitelistUpdated(arr.length, lv);
    }

    /*────────────────── Pausable ──────────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause() external onlyRole(PAUSER_ROLE){_pause();}

    /**
     * @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
     */
    function unpause() external onlyRole(PAUSER_ROLE){_unpause();}

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /*----------- Upgrade authorization -------------*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     * @param newImpl Proposed new implementation address (unused; role gate only).
     */
    function _authorizeUpgrade(address newImpl) internal override onlyRole(ADMIN_ROLE) {}

    /// @dev Storage gap for future variable additions.
    uint256[48] private __gap;
}

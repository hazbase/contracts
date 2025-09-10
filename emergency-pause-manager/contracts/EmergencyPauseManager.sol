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

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/**
 * @dev Minimal Pausable surface used by the manager.
 */
interface IPausable {
    function pause() external;
    function unpause() external;
}

/**
 *  @title EmergencyPauseManager
 *
 *  @notice
 *  - Purpose: Centralized emergency controller to batch `pause()` / `unpause()` a curated
 *             set of target contracts that implement a Pausable-like interface.
 *  - Features:
 *      * Target registry with add/remove (capped by MAX_TARGETS).
 *      * Batch pause by GUARDIAN_ROLE and batch unpause by GOVERNOR_ROLE.
 *      * ERC-2771 meta-transactions support for forwarders.
 *      * UUPS upgradeable; ADMIN_ROLE authorizes upgrades.
 *  - Roles:
 *      * ADMIN_ROLE   — authorize UUPS upgrades (and managed via RolesCommon).
 *      * PAUSER_ROLE  — manage the target registry (register / remove).
 *      * GUARDIAN_ROLE— execute `pauseAll()`.
 *      * GOVERNOR_ROLE— execute `unpauseAll()`.
 *  - Safety & Audit Notes:
 *      * Batch operations use try/catch per target and emit Failure events; the batch
 *        continues for all entries.
 *      * `registerPausable` prevents self-registration to avoid pausing this manager.
 *      * `checkAllPaused()` reads `paused()` on each target via `staticcall` and returns
 *        `false` if any read fails or returns `false`.
 *      * MAX_TARGETS prevents unbounded iteration.
 */
 
contract EmergencyPauseManager is
    RolesCommonUpgradeable,
    ERC2771ContextUpgradeable,
    UUPSUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev Internal registry of managed target contracts.
    EnumerableSet.AddressSet private _targets;

    /// @notice Emitted when a target is registered.
    event TargetRegistered(address indexed target);
    /// @notice Emitted after attempting to pause all targets.
    event PausedAll(address indexed pauser);
    /// @notice Emitted after attempting to unpause all targets.
    event UnpausedAll(address indexed pauser);
    /// @notice Emitted when a target is removed from the registry.
    event TargetRemoved(address indexed target);
    /// @notice Emitted if pausing a specific target failed.
    event PauseFailed(address indexed target);
    /// @notice Emitted if unpausing a specific target failed.
    event UnpauseFailed(address indexed target);

    /// @notice Hard cap on number of registered targets to bound gas/time.
    uint256 public constant MAX_TARGETS = 50;

    /* ---------- Init ---------- */

    /**
     * @notice Disable initializers for the logic contract.
     */
    constructor() { _disableInitializers(); }

    /**
     * @notice Initialize the proxy instance.
     * @param admin       Address granted roles via RolesCommon.
     * @param forwarders  Trusted ERC-2771 forwarders.
     *
     * @dev Calls initializers for ERC2771Context, RolesCommon, and UUPS.
     */
    function initialize(address admin, address[] calldata forwarders) external initializer {
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);
        __UUPSUpgradeable_init();
    }

    /* ---------- Registry ---------- */

    /**
     * @notice Register a new Pausable-compatible target contract.
     * @param target  Target contract address implementing `pause()` / `unpause()`.
     *
     * @dev Requirements:
     *  - Caller must have PAUSER_ROLE.
     *  - `target` cannot be this manager.
     *  - Total targets must remain < MAX_TARGETS.
     *  - No duplicates (set semantics).
     *
     * Emits: `TargetRegistered(target)`.
     *
     * @custom:reverts "limit reached"     if registry is full
     * @custom:reverts "cannot self-register" if `target == address(this)`
     * @custom:reverts "dup"               if already registered
     */
    function registerPausable(address target) external onlyRole(PAUSER_ROLE) {
        require(_targets.length() < MAX_TARGETS, "limit reached");
        require(target != address(this), "cannot self-register");
        require(_targets.add(target), "dup");

        emit TargetRegistered(target);
    }

    /**
     * @notice Remove a previously registered target.
     * @param target  Address to remove.
     *
     * @dev Requirements:
     *  - Caller must have PAUSER_ROLE.
     *  - Target must exist in the set.
     *
     * Emits: `TargetRemoved(target)`.
     *
     * @custom:reverts "missing" if not found
     */
    function removePausable(address target) external onlyRole(PAUSER_ROLE) {
        require(_targets.remove(target), "missing");
        emit TargetRemoved(target);
    }

    /**
     * @notice Return the full list of registered targets.
     * @return address[] Array of target addresses.
     *
     * @dev Uses EnumerableSet.values() which returns a new array in memory.
     */
    function getTargets() external view returns(address[] memory) {
        return _targets.values();
    }

    /* ---------- Pause / Unpause ---------- */

    /**
     * @notice Attempt to call `pause()` on all registered targets.
     *
     * @dev
     *  - Caller must have GUARDIAN_ROLE.
     *  - Each target is paused via `try/catch`; failures emit `PauseFailed(target)`.
     *  - Emits `PausedAll(msg.sender)` after iteration completes (regardless of failures).
     */
    function pauseAll() external onlyRole(GUARDIAN_ROLE) {
        uint256 len = _targets.length();
        for (uint256 i; i < len; ++i) {
            address t = _targets.at(i);
            try IPausable(t).pause() {} catch { emit PauseFailed(t); }
        }
        emit PausedAll(_msgSender());
    }

    /**
     * @notice Attempt to call `unpause()` on all registered targets.
     *
     * @dev
     *  - Caller must have GOVERNOR_ROLE.
     *  - Each target is unpaused via `try/catch`; failures emit `UnpauseFailed(target)`.
     *  - Emits `UnpausedAll(msg.sender)` after iteration completes (regardless of failures).
     */
    function unpauseAll() external onlyRole(GOVERNOR_ROLE) {
        uint256 len = _targets.length();
        for (uint256 i; i < len; ++i) {
            address t = _targets.at(i);
            try IPausable(t).unpause() {} catch { emit UnpauseFailed(t); }
        }
        emit UnpausedAll(_msgSender());
    }

    /**
     * @notice Check whether all registered targets report `paused() == true`.
     * @return allPaused  True if every target responded `true`; false otherwise.
     *
     * @dev
     *  - Uses low-level `staticcall` to `paused()` (no interface requirement).
     *  - If any call fails or returns false, the function returns false.
     */
    function checkAllPaused() external view returns (bool allPaused) {
        for (uint256 i; i < _targets.length(); ++i) {
            (bool ok, bytes memory data) = _targets.at(i).staticcall(
                abi.encodeWithSignature("paused()")
            );
            if (!(ok && abi.decode(data, (bool)))) return false;
        }
        return true;
    }

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /*────────────────────── UUPS auth ────────────────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}
}

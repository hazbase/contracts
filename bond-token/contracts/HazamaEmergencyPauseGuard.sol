// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

interface IHazamaPausableTarget {
    function pause() external;
}

/**
 * @title HazamaEmergencyPauseGuard
 * @notice Gives an emergency multisig a pause-only path. The guard deliberately
 * exposes no unpause call; recovery must be scheduled through governance.
 */
contract HazamaEmergencyPauseGuard is AccessControl {
    bytes32 public constant EMERGENCY_PAUSER_ROLE = keccak256("EMERGENCY_PAUSER_ROLE");

    mapping(address => bool) private _targets;

    event EmergencyPauseTargetUpdated(address indexed target, bool enabled);
    event EmergencyPauseExecuted(address indexed target, address indexed caller);

    constructor(address governanceAdmin, address emergencyPauser, address[] memory initialTargets) {
        require(governanceAdmin != address(0), "ADMIN_ZERO");
        require(emergencyPauser != address(0), "PAUSER_ZERO");
        _grantRole(DEFAULT_ADMIN_ROLE, governanceAdmin);
        _grantRole(EMERGENCY_PAUSER_ROLE, emergencyPauser);
        for (uint256 i = 0; i < initialTargets.length; i++) {
            _setTarget(initialTargets[i], true);
        }
    }

    function setTarget(address target, bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setTarget(target, enabled);
    }

    function pause(address target) external onlyRole(EMERGENCY_PAUSER_ROLE) {
        require(_targets[target], "TARGET_NOT_ALLOWED");
        IHazamaPausableTarget(target).pause();
        emit EmergencyPauseExecuted(target, msg.sender);
    }

    function isTarget(address target) external view returns (bool) {
        return _targets[target];
    }

    function _setTarget(address target, bool enabled) private {
        require(target != address(0), "TARGET_ZERO");
        require(target.code.length > 0, "TARGET_NOT_CONTRACT");
        _targets[target] = enabled;
        emit EmergencyPauseTargetUpdated(target, enabled);
    }
}

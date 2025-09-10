// SPDX-License-Identifier: Apache-2.0 
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";

/// @title RolesCommonUpgradeable
/// @notice Shared role constants & initialiser for upgradeable contracts.
abstract contract RolesCommonUpgradeable is AccessControlEnumerableUpgradeable {
    bytes32 public constant ADMIN_ROLE      = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE     = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE     = keccak256("MINTER_ROLE");
    bytes32 public constant TRANSFER_ROLE   = keccak256("TRANSFER_ROLE");
    bytes32 public constant SOULBOUND_ROLE  = keccak256("SOULBOUND_ROLE");
    bytes32 public constant ROYALTY_ROLE    = keccak256("ROYALTY_ROLE");
    bytes32 public constant GUARDIAN_ROLE   = keccak256("GUARDIAN_ROLE");
    bytes32 public constant GOVERNOR_ROLE   = keccak256("GOVERNOR_ROLE");

    function __RolesCommon_init(address admin) internal onlyInitializing {
        __AccessControlEnumerable_init();
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    function isTransferRoleEmpty() public view returns (bool) {
        return getRoleMemberCount(TRANSFER_ROLE) == 0;
    }

    // storage gap for upgrades
    uint256[45] private __gapRoles;
}
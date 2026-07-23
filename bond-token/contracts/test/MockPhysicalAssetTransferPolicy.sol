// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockPhysicalAssetTransferPolicy {
    mapping(address => bool) private _approved;

    function setApproved(address account, bool approved) external {
        _approved[account] = approved;
    }

    function isWhitelisted(address account) external view returns (bool) {
        return _approved[account];
    }
}

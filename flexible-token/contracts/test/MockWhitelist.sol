// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockWhitelist {
    mapping(address => bool) private _whitelisted;

    function setWhitelisted(address user, bool allowed) external {
        _whitelisted[user] = allowed;
    }

    function isWhitelisted(address user) external view returns (bool) {
        return _whitelisted[user];
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockInitializable {
    address public admin;
    uint256 public value;
    bool public initialized;

    function initialize(address admin_, uint256 value_) external {
        require(!initialized, "already initialized");
        initialized = true;
        admin = admin_;
        value = value_;
    }
}

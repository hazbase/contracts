// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.23;

contract MockMetaTarget {
    uint256 public value;

    event ValueSet(uint256 nextValue);

    function setValue(uint256 nextValue) external {
        value = nextValue;
        emit ValueSet(nextValue);
    }
}

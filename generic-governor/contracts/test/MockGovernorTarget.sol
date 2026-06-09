// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockGovernorTarget {
    uint256 public value;

    event ValueSet(uint256 nextValue);

    function setValue(uint256 nextValue) external {
        value = nextValue;
        emit ValueSet(nextValue);
    }
}

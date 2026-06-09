// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

contract MockReceiver {
    uint256 public count;
    uint256 public rawCount;
    uint256 public lastValue;

    function increment() external payable {
        unchecked { ++count; }
        lastValue = msg.value;
    }

    function incrementBy(uint256 value) external payable {
        count += value;
        lastValue = msg.value;
    }

    receive() external payable {
        unchecked { ++rawCount; }
        lastValue = msg.value;
    }

    fallback() external payable {
        unchecked { ++rawCount; }
        lastValue = msg.value;
    }
}

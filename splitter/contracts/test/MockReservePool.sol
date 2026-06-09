// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockReservePool {
    uint256 public compensationCalls;
    uint256 public liquidityCalls;
    address public lastToken;
    uint256 public lastAmount;
    uint256 public lastValue;
    uint8 public lastBucket;

    function fundCompensation(address token, uint256 amount) external payable {
        compensationCalls += 1;
        lastToken = token;
        lastAmount = amount;
        lastValue = msg.value;
        lastBucket = 1;
    }

    function fundLiquidity(address token, uint256 amount) external payable {
        liquidityCalls += 1;
        lastToken = token;
        lastAmount = amount;
        lastValue = msg.value;
        lastBucket = 2;
    }
}

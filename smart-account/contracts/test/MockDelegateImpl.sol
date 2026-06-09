// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

contract MockDelegateImpl {
    function ping() external pure returns (bytes4) {
        return this.ping.selector;
    }
}

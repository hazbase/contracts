// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

contract SessionSmokeTarget {
    event Marked(address indexed caller, bytes32 indexed tag);

    function mark(bytes32 tag) external returns (bytes32) {
        emit Marked(msg.sender, tag);
        return tag;
    }
}

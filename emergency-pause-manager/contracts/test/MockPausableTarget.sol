// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockPausableTarget {
    bool public paused;
    bool public failPause;
    bool public failUnpause;

    event PauseCalled(address indexed caller);
    event UnpauseCalled(address indexed caller);

    constructor(bool pauseFailure, bool unpauseFailure) {
        failPause = pauseFailure;
        failUnpause = unpauseFailure;
    }

    function setFailures(bool pauseFailure, bool unpauseFailure) external {
        failPause = pauseFailure;
        failUnpause = unpauseFailure;
    }

    function pause() external {
        require(!failPause, 'pause fail');
        paused = true;
        emit PauseCalled(msg.sender);
    }

    function unpause() external {
        require(!failUnpause, 'unpause fail');
        paused = false;
        emit UnpauseCalled(msg.sender);
    }
}

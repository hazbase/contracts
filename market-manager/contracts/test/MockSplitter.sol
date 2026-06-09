// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockSplitter {
    bool public rejectNative;
    uint256 public nativeCalls;
    uint256 public nativeReceived;
    uint256 public erc20Calls;
    uint256 public erc20Received;

    constructor(bool rejectNative_) {
        rejectNative = rejectNative_;
    }

    function setRejectNative(bool rejectNative_) external {
        rejectNative = rejectNative_;
    }

    function routeNative() external payable {
        if (rejectNative) revert("native rejected");
        nativeCalls += 1;
        nativeReceived += msg.value;
    }

    function routeERC20(IERC20 token, uint256 amount) external {
        erc20Calls += 1;
        erc20Received += amount;
        require(token.transferFrom(msg.sender, address(this), amount), "erc20 transfer failed");
    }
}

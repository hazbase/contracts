// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import '@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol';

contract MockSplitter {
    uint256 public nativeCalls;
    uint256 public erc20Calls;

    function routeERC20(IERC20Metadata, uint256) external {
        unchecked { ++erc20Calls; }
    }

    function routeNative() external payable {
        unchecked { ++nativeCalls; }
    }
}

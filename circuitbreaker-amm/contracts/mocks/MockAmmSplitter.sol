// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MockAmmSplitter {
    using SafeERC20 for IERC20;

    bool public rejectERC20;
    bool public rejectNative;

    function setRejectERC20(bool reject) external {
        rejectERC20 = reject;
    }

    function setRejectNative(bool reject) external {
        rejectNative = reject;
    }

    function routeERC20(IERC20Metadata token, uint256 amount) external {
        require(!rejectERC20, "reject-erc20");
        IERC20(address(token)).safeTransferFrom(msg.sender, address(this), amount);
    }

    function routeNative() external payable {
        require(!rejectNative, "reject-native");
    }
}

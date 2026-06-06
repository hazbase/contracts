// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockAmmERC20 is ERC20 {
    uint8 private immutable customDecimals;

    constructor(string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        customDecimals = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return customDecimals;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

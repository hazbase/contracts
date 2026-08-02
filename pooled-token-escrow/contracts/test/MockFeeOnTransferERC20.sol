// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockFeeOnTransferERC20 is ERC20 {
    uint16 public immutable feeBps;

    constructor(uint16 feeBps_) ERC20("Fee Token", "FEE") {
        require(feeBps_ < 10_000, "fee");
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (from != address(0) && to != address(0) && feeBps != 0) {
            uint256 fee = (value * feeBps) / 10_000;
            if (fee != 0) super._update(from, address(0), fee);
            super._update(from, to, value - fee);
            return;
        }
        super._update(from, to, value);
    }
}

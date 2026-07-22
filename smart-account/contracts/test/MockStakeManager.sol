// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

contract MockStakeManager {
    struct StakeInfo {
        uint256 deposit;
        uint256 stake;
        uint32 unstakeDelaySec;
        bool unlocked;
    }

    mapping(address => StakeInfo) public stakeInfo;

    function depositTo(address account) external payable {
        stakeInfo[account].deposit += msg.value;
    }

    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {
        StakeInfo storage info = stakeInfo[msg.sender];
        require(info.deposit >= withdrawAmount, "deposit");
        info.deposit -= withdrawAmount;
        withdrawAddress.transfer(withdrawAmount);
    }

    function addStake(uint32 unstakeDelaySec) external payable {
        StakeInfo storage info = stakeInfo[msg.sender];
        info.stake += msg.value;
        info.unstakeDelaySec = unstakeDelaySec;
        info.unlocked = false;
    }

    function unlockStake() external {
        stakeInfo[msg.sender].unlocked = true;
    }

    function withdrawStake(address payable withdrawAddress) external {
        StakeInfo storage info = stakeInfo[msg.sender];
        require(info.unlocked, "locked");
        uint256 amount = info.stake;
        info.stake = 0;
        withdrawAddress.transfer(amount);
    }
}

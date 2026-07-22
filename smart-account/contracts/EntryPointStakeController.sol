// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IStakeManager} from "@account-abstraction/contracts/interfaces/IStakeManager.sol";

/**
 * @title EntryPointStakeController
 *
 * @notice Shared owner-gated helpers that let ERC-4337 support contracts stake
 * themselves on an EntryPoint. EntryPoint stakes are keyed by `msg.sender`, so
 * these calls must be made by the factory/validator contract itself.
 */
abstract contract EntryPointStakeController {
    event EntryPointDepositAdded(address indexed entryPoint, uint256 amount);
    event EntryPointDepositWithdrawn(address indexed entryPoint, address indexed to, uint256 amount);
    event EntryPointStakeAdded(address indexed entryPoint, uint256 amount, uint32 unstakeDelaySec);
    event EntryPointStakeUnlocked(address indexed entryPoint);
    event EntryPointStakeWithdrawn(address indexed entryPoint, address indexed to);

    modifier onlyEntryPointStakeOwner() {
        _checkEntryPointStakeOwner();
        _;
    }

    function _checkEntryPointStakeOwner() internal view virtual;

    function addEntryPointDeposit(address entryPoint) external payable onlyEntryPointStakeOwner {
        require(entryPoint.code.length > 0, "entrypoint-code");
        require(msg.value > 0, "deposit0");
        IStakeManager(entryPoint).depositTo{value: msg.value}(address(this));
        emit EntryPointDepositAdded(entryPoint, msg.value);
    }

    function withdrawEntryPointDeposit(
        address entryPoint,
        address payable to,
        uint256 amount
    ) external onlyEntryPointStakeOwner {
        require(entryPoint.code.length > 0, "entrypoint-code");
        require(to != address(0), "to0");
        require(amount > 0, "amount0");
        IStakeManager(entryPoint).withdrawTo(to, amount);
        emit EntryPointDepositWithdrawn(entryPoint, to, amount);
    }

    function addEntryPointStake(
        address entryPoint,
        uint32 unstakeDelaySec
    ) external payable onlyEntryPointStakeOwner {
        require(entryPoint.code.length > 0, "entrypoint-code");
        require(msg.value > 0, "stake0");
        IStakeManager(entryPoint).addStake{value: msg.value}(unstakeDelaySec);
        emit EntryPointStakeAdded(entryPoint, msg.value, unstakeDelaySec);
    }

    function unlockEntryPointStake(address entryPoint) external onlyEntryPointStakeOwner {
        require(entryPoint.code.length > 0, "entrypoint-code");
        IStakeManager(entryPoint).unlockStake();
        emit EntryPointStakeUnlocked(entryPoint);
    }

    function withdrawEntryPointStake(
        address entryPoint,
        address payable to
    ) external onlyEntryPointStakeOwner {
        require(entryPoint.code.length > 0, "entrypoint-code");
        require(to != address(0), "to0");
        IStakeManager(entryPoint).withdrawStake(to);
        emit EntryPointStakeWithdrawn(entryPoint, to);
    }
}

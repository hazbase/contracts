// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

import "./AccountFactoryV2.sol";
import "./EntryPointStakeController.sol";

/**
 * @title AccountFactoryV3
 *
 * @notice Deterministic SmartAccountV2 factory with owner-gated EntryPoint stake
 * controls for ERC-4337 bundler compatibility.
 */
contract AccountFactoryV3 is AccountFactoryV2, Ownable2Step, EntryPointStakeController {
    constructor(
        address _impl,
        address _entryPoint,
        address _safe,
        address initialOwner
    ) AccountFactoryV2(_impl, _entryPoint, _safe) Ownable(initialOwner) {
        require(initialOwner != address(0), "owner0");
    }

    function _checkEntryPointStakeOwner() internal view override {
        _checkOwner();
    }
}

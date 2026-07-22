// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/**
 * @title HazamaGovernanceTimelock
 * @notice Applies a mandatory delay between multisig approval and privileged
 * changes to the HAZAMA RWA settlement contracts.
 */
contract HazamaGovernanceTimelock is TimelockController {
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        address bootstrapAdmin
    ) TimelockController(minDelay, proposers, executors, bootstrapAdmin) {}
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import {IOwnerValidator} from "./IOwnerValidator.sol";

/// @title IOwnerValidatorV2
/// @notice Bundler-safe owner validator interface for SmartAccountV2.
/// @dev The owner validator still exposes the legacy bool-based methods for
/// config hashing and ERC-1271 compatibility, but userOp validation now returns
/// ERC-4337 packed validationData so timestamp windows can be enforced by the
/// EntryPoint path instead of direct validator-side timestamp branching.
interface IOwnerValidatorV2 is IOwnerValidator {
    /// @notice Validates an owner-scoped ERC-4337 user operation and returns packed validationData.
    /// @param account The SmartAccount instance that is requesting validation.
    /// @param ownerConfigHash The committed owner config hash currently stored by the account.
    /// @param userOpHash The canonical user operation hash supplied by the EntryPoint flow.
    /// @param signature Validator-defined payload used to prove ownership for this user operation.
    /// @return validationData ERC-4337 packed validationData containing the validity window.
    function validateUserOpValidationData(
        address account,
        bytes32 ownerConfigHash,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view returns (uint256 validationData);
}

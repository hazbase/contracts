// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

/// @title IOwnerValidator
/// @notice Pluggable owner-validation interface for SmartAccount.
/// @dev Implementations decide how account ownership is proven for both ERC-4337
/// user operations and ERC-1271 style digest checks. The SmartAccount only stores
/// the validator address and a committed `ownerConfigHash`; it does not interpret
/// the validator-specific owner config by itself.
interface IOwnerValidator {
    /// @notice Returns the canonical commitment used by SmartAccount for a validator-specific owner config.
    /// @dev Validators are free to define the binary format of `ownerConfig`, but they must produce
    /// a stable hash so account bootstrap, rotation, and recovery can compare configurations safely.
    function configHash(bytes calldata ownerConfig) external pure returns (bytes32);

    /// @notice Validates an owner-scoped ERC-4337 user operation.
    /// @param account The SmartAccount instance that is requesting validation.
    /// @param ownerConfigHash The committed owner config hash currently stored by the account.
    /// @param userOpHash The canonical user operation hash supplied by the EntryPoint flow.
    /// @param signature Validator-defined payload used to prove ownership for this user operation.
    function validateUserOpSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view returns (bool);

    /// @notice Validates an owner-scoped digest for ERC-1271 style signature checks.
    /// @param account The SmartAccount instance that is requesting validation.
    /// @param ownerConfigHash The committed owner config hash currently stored by the account.
    /// @param digest The digest that should be approved by the account owner.
    /// @param signature Validator-defined payload used to prove ownership for this digest.
    function isValidSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 digest,
        bytes calldata signature
    ) external view returns (bool);
}

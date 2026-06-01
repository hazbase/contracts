// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IOwnerValidator} from "./interfaces/IOwnerValidator.sol";
import {IOwnerValidatorV2} from "./interfaces/IOwnerValidatorV2.sol";

/**
 * @title PasskeyOwnerValidatorV3
 *
 * @notice Passkey-backed owner validator with a rotatable backend authorizer.
 *
 * @dev
 * - Smart account addresses are keyed by the validator address, owner config hash,
 *   and salt. Keeping this validator address stable lets future KMS rotations swap
 *   the trusted authorizer without changing future predicted account addresses.
 * - Ownership should be assigned to an operational Safe/timelock rather than an EOA.
 */
contract PasskeyOwnerValidatorV3 is IOwnerValidatorV2, Ownable2Step {
    using ECDSA for bytes32;

    /// @dev Domain used when the backend authorizer signs approval for an ERC-4337 user operation.
    bytes32 private constant USER_OP_DOMAIN = keccak256("hazbase.passkey.owner.userop.v1");
    /// @dev Domain used when the backend authorizer signs approval for an arbitrary digest / ERC-1271 check.
    bytes32 private constant DIGEST_DOMAIN = keccak256("hazbase.passkey.owner.digest.v1");

    /// @notice Backend signer that attests a passkey ceremony was verified for the expected account/config.
    address public authorizer;

    event AuthorizerChanged(address indexed previousAuthorizer, address indexed newAuthorizer);

    /// @param initialAuthorizer Trusted backend signer that authorizes owner actions after passkey verification.
    /// @param initialOwner Operational owner that can rotate the backend authorizer.
    constructor(address initialAuthorizer, address initialOwner) Ownable(initialOwner) {
        require(initialAuthorizer != address(0), "authorizer0");
        authorizer = initialAuthorizer;
        emit AuthorizerChanged(address(0), initialAuthorizer);
    }

    /// @notice Rotates the trusted backend signer without changing this validator address.
    function setAuthorizer(address newAuthorizer) external onlyOwner {
        require(newAuthorizer != address(0), "authorizer0");
        address previousAuthorizer = authorizer;
        require(newAuthorizer != previousAuthorizer, "authorizer-same");
        authorizer = newAuthorizer;
        emit AuthorizerChanged(previousAuthorizer, newAuthorizer);
    }

    /// @inheritdoc IOwnerValidator
    function configHash(bytes calldata ownerConfig) external pure override returns (bytes32) {
        return keccak256(ownerConfig);
    }

    /// @inheritdoc IOwnerValidator
    function validateUserOpSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view override returns (bool) {
        (bool structurallyValid,,) = _verifyUserOpPayload(account, ownerConfigHash, userOpHash, signature);
        return structurallyValid;
    }

    /// @inheritdoc IOwnerValidatorV2
    function validateUserOpValidationData(
        address account,
        bytes32 ownerConfigHash,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view override returns (uint256 validationData) {
        (bool structurallyValid, uint48 validUntil, uint48 validAfter) =
            _verifyUserOpPayload(account, ownerConfigHash, userOpHash, signature);
        return _packValidationData(!structurallyValid, validUntil, validAfter);
    }

    /// @inheritdoc IOwnerValidator
    function isValidSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 digest,
        bytes calldata signature
    ) external view override returns (bool) {
        (bool structurallyValid, uint48 validUntil, uint48 validAfter) =
            _verifyPayload(DIGEST_DOMAIN, account, ownerConfigHash, digest, signature);
        if (!structurallyValid) return false;
        return block.timestamp >= uint256(validAfter) && block.timestamp <= uint256(validUntil);
    }

    function _verifyUserOpPayload(
        address account,
        bytes32 expectedOwnerConfigHash,
        bytes32 payloadHash,
        bytes calldata signature
    ) internal view returns (bool structurallyValid, uint48 validUntil, uint48 validAfter) {
        return _verifyPayload(USER_OP_DOMAIN, account, expectedOwnerConfigHash, payloadHash, signature);
    }

    function _verifyPayload(
        bytes32 domain,
        address account,
        bytes32 expectedOwnerConfigHash,
        bytes32 payloadHash,
        bytes calldata signature
    ) internal view returns (bool structurallyValid, uint48 validUntil, uint48 validAfter) {
        (uint48 decodedValidUntil, uint48 decodedValidAfter, bytes32 providedOwnerConfigHash, bytes memory authorizerSignature) =
            abi.decode(signature, (uint48, uint48, bytes32, bytes));

        validUntil = decodedValidUntil;
        validAfter = decodedValidAfter;
        if (providedOwnerConfigHash != expectedOwnerConfigHash) return (false, validUntil, validAfter);
        if (validUntil == 0 || validUntil < validAfter) return (false, validUntil, validAfter);

        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encode(
                    domain,
                    block.chainid,
                    address(this),
                    account,
                    expectedOwnerConfigHash,
                    payloadHash,
                    validUntil,
                    validAfter
                )
            )
        );

        structurallyValid = hash.recover(authorizerSignature) == authorizer;
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return uint256(sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }
}

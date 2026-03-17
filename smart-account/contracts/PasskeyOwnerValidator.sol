// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IOwnerValidator} from "./interfaces/IOwnerValidator.sol";

/**
 * @title PasskeyOwnerValidator
 *
 * @notice
 * - Purpose: Owner validator for passkey-backed smart accounts.
 * - This validator does not rely on browser-held secp256k1 owner keys.
 * - A trusted backend authorizer verifies the WebAuthn assertion off-chain and
 *   signs a compact attestation over `(account, ownerConfigHash, payloadHash, validity window)`.
 *
 * @dev
 * - `ownerConfig` is opaque bytes to the validator and is committed to via `configHash`.
 * - The expected usage is `abi.encode(credentialIdHash, rpIdHash, qx, qy, metadata...)`.
 * - The backend authorizer must only sign after validating passkey registration/assertion
 *   against the configured credential and RP binding.
 */
contract PasskeyOwnerValidator is IOwnerValidator {
    using ECDSA for bytes32;

    /// @dev Domain used when the backend authorizer signs approval for an ERC-4337 user operation.
    bytes32 private constant USER_OP_DOMAIN = keccak256("hazbase.passkey.owner.userop.v1");
    /// @dev Domain used when the backend authorizer signs approval for an arbitrary digest / ERC-1271 check.
    bytes32 private constant DIGEST_DOMAIN = keccak256("hazbase.passkey.owner.digest.v1");

    /// @notice Backend signer that attests a passkey ceremony was verified for the expected account/config.
    address public immutable authorizer;

    /// @param _authorizer Trusted backend signer that authorizes owner actions after passkey verification.
    constructor(address _authorizer) {
        require(_authorizer != address(0), "authorizer0");
        authorizer = _authorizer;
    }

    /// @inheritdoc IOwnerValidator
    function configHash(bytes calldata ownerConfig) external pure override returns (bytes32) {
        return keccak256(ownerConfig);
    }

    /// @inheritdoc IOwnerValidator
    /// @dev The validator never checks WebAuthn data directly on-chain in this version.
    /// It verifies a compact backend attestation over `(domain, chainid, validator, account,
    /// ownerConfigHash, payloadHash, validUntil, validAfter)`.
    function validateUserOpSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 userOpHash,
        bytes calldata signature
    ) external view override returns (bool) {
        return _verify(USER_OP_DOMAIN, account, ownerConfigHash, userOpHash, signature);
    }

    /// @inheritdoc IOwnerValidator
    function isValidSignature(
        address account,
        bytes32 ownerConfigHash,
        bytes32 digest,
        bytes calldata signature
    ) external view override returns (bool) {
        return _verify(DIGEST_DOMAIN, account, ownerConfigHash, digest, signature);
    }

    function _verify(
        bytes32 domain,
        address account,
        bytes32 expectedOwnerConfigHash,
        bytes32 payloadHash,
        bytes calldata signature
    ) internal view returns (bool) {
        // The validator payload is intentionally compact so frontend/backend flows can
        // treat the backend authorizer signature as the only on-chain owner proof artifact.
        (uint48 validUntil, uint48 validAfter, bytes32 providedOwnerConfigHash, bytes memory authorizerSignature) =
            abi.decode(signature, (uint48, uint48, bytes32, bytes));

        if (providedOwnerConfigHash != expectedOwnerConfigHash) return false;
        if (validUntil == 0 || validUntil < validAfter) return false;
        if (block.timestamp < uint256(validAfter) || block.timestamp > uint256(validUntil)) return false;

        // Bind the attestation to chain, validator instance, account, config hash, and payload hash
        // so a signature cannot be replayed across accounts or validators.
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

        return hash.recover(authorizerSignature) == authorizer;
    }
}

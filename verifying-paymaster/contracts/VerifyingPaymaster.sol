// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______    
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\   
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\   
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\ 
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/                                                                         
//
//    https://hazbase.com

import "@account-abstraction/contracts/core/BasePaymaster.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title VerifyingPaymaster
 *
 * @notice
 * - Purpose: A simple **ERC-4337 paymaster** that validates a user operation
 *   against an **off-chain signature** produced by a trusted `verifyingSigner`.
 *   It also enforces a **sender-scoped nonce** and optional validity window
 *   (`validAfter`..`validUntil`) embedded in `paymasterAndData`.
 *
 * - Flow:
 *   1) Client builds a UserOperation and computes `getHash(userOp, validUntil, validAfter)`.
 *   2) Off-chain service signs the **eth-signed** hash with `verifyingSigner`.
 *   3) The signature together with timestamps is appended to `paymasterAndData`:
 *      `[paymaster(20) | validUntil(6) | validAfter(6) | signature(64/65)]`.
 *   4) EntryPoint calls `_validatePaymasterUserOp` → signature is recovered and
 *      compared to `verifyingSigner`. On success, the op is sponsored.
 *
 * @dev SECURITY / AUDIT NOTES
 * - **Hash domain** includes: packed userOp (excl. paymasterAndData), `chainid`,
 *   this paymaster address, a **sender-scoped nonce**, and the validity window.
 * - `senderNonce` is incremented **on every validation attempt**, preventing replay
 *   of the same signed request from the same `sender`. If you prefer increment only
 *   after success, move the increment below the signature check.
 * - `pack(userOp)` copies calldata bytes up to (but not including) `paymasterAndData`.
 * - Signature scheme uses `toEthSignedMessageHash` (EIP-191). Align your off-chain
 *   signing accordingly (or switch both ends to EIP-712).
 */

contract VerifyingPaymaster is BasePaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    /// @notice Emitted when the verifying signer is changed by the owner.
    event SignerChanged(address indexed signer);

    /// @notice Address that must sign off-chain approvals for sponsorship.
    address public verifyingSigner;

    /// @dev Byte offsets inside `paymasterAndData` for timestamp fields and signature.
    uint256 private constant VALID_TIMESTAMP_OFFSET = 20; // skip paymaster (20 bytes)
    uint256 private constant SIGNATURE_OFFSET = 84;       // 20 + 6 + 6 + 52? (aligned to start of signature)

    /// @notice Per-sender anti-replay nonce included in `getHash`.
    mapping(address => uint256) public senderNonce;

    /**
     * @notice Deploy the paymaster.
     * @param _entryPoint       ERC-4337 EntryPoint.
     * @param _verifyingSigner  Off-chain signer used for approvals.
     *
     * @dev Emits `SignerChanged`.
     */
    constructor(IEntryPoint _entryPoint, address _verifyingSigner) BasePaymaster(_entryPoint) {
        verifyingSigner = _verifyingSigner;
        emit SignerChanged(_verifyingSigner);
    }

    /*────────────────────────── Hashing helpers ─────────────────────────*/

    /**
     * @notice Pack the UserOperation calldata **excluding** `paymasterAndData`.
     * @param userOp UserOperation (calldata).
     * @return ret   ABI-encoded prefix of the userOp up to `paymasterAndData`.
     *
     * @dev Assembly copies raw calldata slice to avoid re-encoding paymaster fields.
     */
    function pack(UserOperation calldata userOp) internal pure returns (bytes memory ret) {
        bytes calldata pnd = userOp.paymasterAndData;
        assembly {
            let ofs := userOp
            let len := sub(sub(pnd.offset, ofs), 32)
            ret := mload(0x40)
            mstore(0x40, add(ret, add(len, 32)))
            mstore(ret, len)
            calldatacopy(add(ret, 32), ofs, len)
        }
    }

    /**
     * @notice Compute the hash to be signed off-chain by `verifyingSigner`.
     * @param userOp     The user operation (calldata).
     * @param validUntil Latest validity timestamp (inclusive). 0 means “no limit”.
     * @param validAfter Earliest validity timestamp (inclusive). 0 means “immediately”.
     * @return bytes32   Keccak256 hash over the packed fields and domain separators.
     *
     * @dev Hash domain: `pack(userOp)`, `chainid`, `this`, `senderNonce[userOp.getSender()]`,
     *      `validUntil`, `validAfter`.
     */
    function getHash(
        UserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    pack(userOp),
                    block.chainid,
                    address(this),
                    senderNonce[userOp.getSender()],
                    validUntil,
                    validAfter
                )
            );
    }

    /*────────────────────────── Paymaster validation ─────────────────────*/

    /**
     * @notice EntryPoint hook to validate a sponsored user operation.
     * @param userOp          The incoming UserOperation.
     * @param userOpHash      Hash computed by EntryPoint (unused; we recompute domain hash).
     * @param requiredPreFund Pre-fund amount EntryPoint expects (unused here).
     * @return context        Opaque context (empty here).
     * @return validationData Packed validation data (sig failure / validAfter / validUntil).
     *
     * @dev
     * - Parses `(validUntil, validAfter, signature)` from `userOp.paymasterAndData`.
     * - Recovers signer from `toEthSignedMessageHash(getHash(...))`.
     * - Increments `senderNonce[sender]` (anti-replay) **before** signature check.
     * - On signer mismatch → returns `_packValidationData(true, validUntil, validAfter)`
     *   which signals **signature failure** to EntryPoint.
     * - On success → returns `_packValidationData(false, validUntil, validAfter)`.
     *
     * @custom:reverts VerifyingPaymaster: invalid signature length in paymasterAndData
     *          if signature length not 64/65 bytes
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32, /*userOpHash*/
        uint256 requiredPreFund
    ) internal override returns (bytes memory context, uint256 validationData) {
        (requiredPreFund); // silence warning

        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = parsePaymasterAndData(
            userOp.paymasterAndData
        );
        require(
            signature.length == 64 || signature.length == 65,
            "VerifyingPaymaster: invalid signature length in paymasterAndData"
        );

        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));
        senderNonce[userOp.getSender()]++;

        if (verifyingSigner != ECDSA.recover(hash, signature)) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        return ("", _packValidationData(false, validUntil, validAfter));
    }

    /**
     * @notice Decode validity window and signature from `paymasterAndData`.
     * @param paymasterAndData Raw bytes passed in the UserOperation.
     * @return validUntil  Latest validity timestamp (uint48).
     * @return validAfter  Earliest validity timestamp (uint48).
     * @return signature   ECDSA signature bytes (64/65 bytes).
     *
     * @dev Layout: `[20 bytes paymaster | 6 bytes validUntil | 6 bytes validAfter | signature...]`.
     */
    function parsePaymasterAndData(bytes calldata paymasterAndData)
        public
        pure
        returns (
            uint48 validUntil,
            uint48 validAfter,
            bytes calldata signature
        )
    {
        (validUntil, validAfter) = abi.decode(
            paymasterAndData[VALID_TIMESTAMP_OFFSET:SIGNATURE_OFFSET],
            (uint48, uint48)
        );
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    /*────────────────────────── Admin ─────────────────────────*/

    /**
     * @notice Update the verifying signer.
     * @param _verifyingSigner New signer address used for approvals.
     *
     * @dev Only the contract **owner** (BasePaymaster’s Ownable) may call.
     *      Emits `SignerChanged`.
     */
    function changeSigner(address _verifyingSigner) external onlyOwner {
        verifyingSigner = _verifyingSigner;
        emit SignerChanged(_verifyingSigner);
    }
}

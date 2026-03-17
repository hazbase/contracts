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
 * - Purpose: A simple ERC-4337 paymaster that validates a user operation
 *   against an off-chain signature produced by a trusted `verifyingSigner`.
 * - This version keeps the policy signer-centric but adds on-chain guardrails
 *   for validity windows and gas limits to reduce configuration mistakes.
 */
contract VerifyingPaymaster is BasePaymaster {
    using ECDSA for bytes32;
    using UserOperationLib for UserOperation;

    event SignerChanged(address indexed signer);
    event GuardrailsUpdated(uint48 maxValidityWindow, uint256 maxCallGasLimit, uint256 maxVerificationGasLimit);
    event PauseUpdated(bool paused);

    /// @notice Off-chain signer trusted to approve sponsorable user operations.
    address public verifyingSigner;
    /// @notice Maximum allowed `validUntil - validAfter` window for a sponsor signature.
    uint48 public maxValidityWindow;
    /// @notice Upper bound for `userOp.callGasLimit` accepted by the paymaster.
    uint256 public maxCallGasLimit;
    /// @notice Upper bound for `userOp.verificationGasLimit` accepted by the paymaster.
    uint256 public maxVerificationGasLimit;
    /// @notice Emergency pause switch for sponsor validation.
    bool public paused;

    /// @dev Byte range inside `paymasterAndData` where `(validUntil, validAfter)` begins.
    uint256 private constant VALID_TIMESTAMP_OFFSET = 20;
    /// @dev Byte offset where the signature payload begins after address + packed validity window.
    uint256 private constant SIGNATURE_OFFSET = 84;

    /// @notice Replay nonce tracked per sender for off-chain sponsor signatures.
    /// @dev The backend signing service is expected to read this value before producing `paymasterAndData`.
    mapping(address => uint256) public senderNonce;

    /// @param _entryPoint ERC-4337 EntryPoint served by this paymaster.
    /// @param _verifyingSigner Off-chain signer that authorizes sponsorship.
    constructor(IEntryPoint _entryPoint, address _verifyingSigner) BasePaymaster(_entryPoint) {
        verifyingSigner = _verifyingSigner;
        maxValidityWindow = 1 hours;
        maxCallGasLimit = 1_000_000;
        maxVerificationGasLimit = 1_000_000;
        emit SignerChanged(_verifyingSigner);
        emit GuardrailsUpdated(maxValidityWindow, maxCallGasLimit, maxVerificationGasLimit);
    }

    /// @notice Returns the canonical user-operation bytes hashed by the backend signer.
    /// @dev This intentionally excludes the trailing `paymasterAndData` signature bytes because those
    /// do not exist yet at signing time.
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

    /// @notice Computes the sponsor-signing hash expected by the backend paymaster signer.
    /// @dev The hash is bound to chain, paymaster address, sender nonce, and validity window so
    /// signatures cannot be replayed across chains, paymaster instances, or sender-nonce epochs.
    function getHash(
        UserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        return keccak256(
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

    /// @inheritdoc BasePaymaster
    /// @dev This function keeps the paymaster signer-centric by design. Policy allowlisting, per-session
    /// budgets, and action-profile decisions are enforced off-chain before a signature reaches this contract.
    /// On-chain guardrails only reject obviously unsafe or misconfigured payloads.
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 requiredPreFund
    ) internal override returns (bytes memory context, uint256 validationData) {
        (userOpHash, requiredPreFund);

        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = parsePaymasterAndData(
            userOp.paymasterAndData
        );
        require(
            signature.length == 64 || signature.length == 65,
            "VerifyingPaymaster: invalid signature length in paymasterAndData"
        );

        if (paused) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }
        if (validUntil == 0 || validUntil < validAfter) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }
        if (uint256(validUntil) - uint256(validAfter) > uint256(maxValidityWindow)) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }
        if (userOp.callGasLimit > maxCallGasLimit) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }
        if (userOp.verificationGasLimit > maxVerificationGasLimit) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));
        address recovered = ECDSA.recover(hash, signature);
        if (verifyingSigner != recovered) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        // Nonce is consumed only after the signer check succeeds so invalid payloads cannot
        // grief a sender by burning future sponsorship signatures.
        senderNonce[userOp.getSender()]++;
        return ("", _packValidationData(false, validUntil, validAfter));
    }

    /// @notice Decodes the packed validity window and backend signature from `paymasterAndData`.
    /// @dev The format is `[20-byte paymaster address][uint48 validUntil][uint48 validAfter][signature...]`.
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

    /// @notice Updates the trusted backend signer used for sponsor authorization.
    function changeSigner(address _verifyingSigner) external onlyOwner {
        verifyingSigner = _verifyingSigner;
        emit SignerChanged(_verifyingSigner);
    }

    /// @notice Updates the on-chain guardrails that cap sponsor validity windows and gas limits.
    /// @dev These limits are intended to constrain backend misconfiguration, not to replace backend
    /// action-profile enforcement.
    function setGuardrails(
        uint48 _maxValidityWindow,
        uint256 _maxCallGasLimit,
        uint256 _maxVerificationGasLimit
    ) external onlyOwner {
        require(
            _maxValidityWindow > 0 && _maxCallGasLimit > 0 && _maxVerificationGasLimit > 0,
            "guardrail0"
        );
        maxValidityWindow = _maxValidityWindow;
        maxCallGasLimit = _maxCallGasLimit;
        maxVerificationGasLimit = _maxVerificationGasLimit;
        emit GuardrailsUpdated(_maxValidityWindow, _maxCallGasLimit, _maxVerificationGasLimit);
    }

    /// @notice Pauses all new sponsor approvals at the paymaster level.
    function pause() external onlyOwner {
        paused = true;
        emit PauseUpdated(true);
    }

    /// @notice Resumes sponsor approvals after an operational pause.
    function unpause() external onlyOwner {
        paused = false;
        emit PauseUpdated(false);
    }
}

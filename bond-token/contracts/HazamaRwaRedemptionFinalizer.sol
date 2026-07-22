// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

interface IGenericRwaRedemptionRecorder {
    enum TokenStandard {
        ERC3475,
        ERC20,
        ERC721,
        ERC1155
    }

    function recordRedemption(
        bytes32 redemptionId,
        TokenStandard tokenStandard,
        address token,
        address holder,
        uint256 classId,
        uint256 nonceId,
        uint256 amount,
        bytes32 liquidAssetId,
        bytes32 liquidRecoveryTxid,
        uint32 liquidRecoveryVout,
        bytes32 termsHash,
        bytes32 evidenceHash
    ) external returns (bytes32);
}

/**
 * @title HazamaRwaRedemptionFinalizer
 * @notice Public, quorum-gated finalizer for Liquid RWA redemptions recorded on EVM.
 *
 * Any caller may submit a valid HAZAMA proof. This contract verifies a threshold
 * of independent EIP-712 redemption attestations, then records the redemption
 * through the existing GenericRwaRedemptionManager after it has been granted
 * RECORDER_ROLE. The caller is an executor, not an approver.
 */
contract HazamaRwaRedemptionFinalizer is AccessControl, EIP712, Pausable, ReentrancyGuard {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant HAZAMA_APPROVER_ADMIN_ROLE = keccak256("HAZAMA_APPROVER_ADMIN_ROLE");

    bytes32 private constant _HAZAMA_REDEMPTION_ATTESTATION_TYPEHASH = keccak256(
        "HazamaRedemptionAttestation(string templateId,string redemptionRequestId,string assetBindingId,bytes32 termsHash,uint256 sourceChainId,address sourceContract,string tokenStandard,address token,uint256 classId,uint256 nonceId,address holderEvmAddress,string liquidNetwork,string liquidTxid,uint32 recoveryVout,string recoveryAssetId,uint256 recoveryAmount,bytes32 vaultAddressHash,uint256 confirmations,uint64 observedAt,uint64 expiresAt)"
    );

    struct RedemptionRecordInput {
        bytes32 redemptionId;
        IGenericRwaRedemptionRecorder.TokenStandard tokenStandard;
        address token;
        address holder;
        uint256 classId;
        uint256 nonceId;
        uint256 amount;
        bytes32 liquidAssetId;
        bytes32 liquidRecoveryTxid;
        uint32 liquidRecoveryVout;
        bytes32 termsHash;
    }

    struct RedemptionAttestation {
        string templateId;
        string redemptionRequestId;
        string assetBindingId;
        bytes32 termsHash;
        uint256 sourceChainId;
        address sourceContract;
        string tokenStandard;
        address token;
        uint256 classId;
        uint256 nonceId;
        address holderEvmAddress;
        string liquidNetwork;
        string liquidTxid;
        uint32 recoveryVout;
        string recoveryAssetId;
        uint256 recoveryAmount;
        bytes32 vaultAddressHash;
        uint256 confirmations;
        uint64 observedAt;
        uint64 expiresAt;
    }

    IGenericRwaRedemptionRecorder public immutable redemptionManager;
    mapping(address => bool) private _hazamaApprovers;
    uint256 private _hazamaApproverCount;
    uint256 private _hazamaThreshold;

    event HazamaApproverUpdated(address indexed approver, bool enabled);
    event HazamaThresholdUpdated(uint256 threshold);
    event RedemptionFinalized(
        bytes32 indexed redemptionId,
        bytes32 indexed attestationDigest,
        address indexed finalizer,
        uint256 signatureCount
    );

    constructor(address admin, address redemptionManagerAddress)
        EIP712("HAZAMA Redemption Attestation", "1")
    {
        require(admin != address(0), "ADMIN_ZERO");
        require(redemptionManagerAddress != address(0), "REDEMPTION_MANAGER_ZERO");
        redemptionManager = IGenericRwaRedemptionRecorder(redemptionManagerAddress);
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(HAZAMA_APPROVER_ADMIN_ROLE, admin);
    }

    /**
     * @notice Records a redemption after validating the configured HAZAMA quorum.
     * @dev Callable by anyone. Approver signatures, not msg.sender, authorize the action.
     */
    function finalizeRedemption(
        RedemptionRecordInput calldata record,
        RedemptionAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant returns (bytes32) {
        bytes32 attestationDigest = _verifyHazamaQuorum(record, attestations, signatures);
        redemptionManager.recordRedemption(
            record.redemptionId,
            record.tokenStandard,
            record.token,
            record.holder,
            record.classId,
            record.nonceId,
            record.amount,
            record.liquidAssetId,
            record.liquidRecoveryTxid,
            record.liquidRecoveryVout,
            record.termsHash,
            attestationDigest
        );

        emit RedemptionFinalized(record.redemptionId, attestationDigest, msg.sender, signatures.length);
        return record.redemptionId;
    }

    function setHazamaApprover(address approver, bool enabled)
        external
        onlyRole(HAZAMA_APPROVER_ADMIN_ROLE)
    {
        require(approver != address(0), "APPROVER_ZERO");
        if (_hazamaApprovers[approver] == enabled) return;

        _hazamaApprovers[approver] = enabled;
        if (enabled) {
            _hazamaApproverCount += 1;
        } else {
            _hazamaApproverCount -= 1;
            require(_hazamaThreshold <= _hazamaApproverCount, "THRESHOLD_GT_APPROVERS");
        }
        emit HazamaApproverUpdated(approver, enabled);
    }

    function setHazamaThreshold(uint256 threshold)
        external
        onlyRole(HAZAMA_APPROVER_ADMIN_ROLE)
    {
        require(threshold > 0, "THRESHOLD_ZERO");
        require(threshold <= _hazamaApproverCount, "THRESHOLD_GT_APPROVERS");
        _hazamaThreshold = threshold;
        emit HazamaThresholdUpdated(threshold);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function hazamaApprover(address approver) external view returns (bool) {
        return _hazamaApprovers[approver];
    }

    function hazamaApproverCount() external view returns (uint256) {
        return _hazamaApproverCount;
    }

    function hazamaThreshold() external view returns (uint256) {
        return _hazamaThreshold;
    }

    function _verifyHazamaQuorum(
        RedemptionRecordInput calldata record,
        RedemptionAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) private view returns (bytes32 attestationDigest) {
        uint256 threshold = _hazamaThreshold;
        require(threshold > 0, "HAZAMA_THRESHOLD_ZERO");
        require(attestations.length == signatures.length, "HAZAMA_ATTESTATION_LENGTH");
        require(signatures.length >= threshold, "HAZAMA_QUORUM_NOT_MET");

        address[] memory accepted = new address[](signatures.length);
        uint256 count = 0;
        bytes32 firstDigest = bytes32(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            _validateAttestation(record, attestations[i]);
            bytes32 digest = _hashTypedDataV4(_hashRedemptionAttestation(attestations[i]));
            if (i == 0) {
                firstDigest = digest;
            } else {
                require(digest == firstDigest, "HAZAMA_ATTESTATION_MISMATCH");
            }
            address signer = ECDSA.recover(digest, signatures[i]);
            require(_hazamaApprovers[signer], "HAZAMA_APPROVER_INVALID");
            for (uint256 j = 0; j < count; j++) {
                require(accepted[j] != signer, "HAZAMA_DUPLICATE_SIGNER");
            }
            accepted[count] = signer;
            count += 1;
        }

        require(count >= threshold, "HAZAMA_QUORUM_NOT_MET");
        return firstDigest;
    }

    function _validateAttestation(
        RedemptionRecordInput calldata record,
        RedemptionAttestation calldata attestation
    ) private view {
        require(record.redemptionId != bytes32(0), "REDEMPTION_ID_ZERO");
        require(record.token != address(0), "TOKEN_ZERO");
        require(record.holder != address(0), "HOLDER_ZERO");
        require(record.amount > 0, "AMOUNT_ZERO");
        require(record.liquidAssetId != bytes32(0), "LIQUID_ASSET_ZERO");
        require(record.liquidRecoveryTxid != bytes32(0), "RECOVERY_TX_ZERO");
        require(record.termsHash != bytes32(0), "TERMS_HASH_ZERO");

        require(keccak256(bytes(attestation.redemptionRequestId)) == record.redemptionId, "ATTEST_REDEMPTION_ID");
        require(attestation.termsHash == record.termsHash, "ATTEST_TERMS_HASH");
        require(attestation.sourceChainId == block.chainid, "ATTEST_CHAIN_ID");
        require(attestation.sourceContract == address(this), "ATTEST_SOURCE");
        require(keccak256(bytes(attestation.tokenStandard)) == keccak256(bytes(_tokenStandardName(record.tokenStandard))), "ATTEST_STANDARD");
        require(attestation.token == record.token, "ATTEST_TOKEN");
        require(attestation.classId == record.classId, "ATTEST_CLASS_ID");
        require(attestation.nonceId == record.nonceId, "ATTEST_NONCE_ID");
        require(attestation.holderEvmAddress == record.holder, "ATTEST_HOLDER");
        require(_bytes32FromHexString(attestation.liquidTxid) == record.liquidRecoveryTxid, "ATTEST_TXID");
        require(attestation.recoveryVout == record.liquidRecoveryVout, "ATTEST_VOUT");
        require(_bytes32FromHexString(attestation.recoveryAssetId) == record.liquidAssetId, "ATTEST_ASSET");
        require(attestation.recoveryAmount == record.amount, "ATTEST_AMOUNT");
        require(attestation.vaultAddressHash != bytes32(0), "ATTEST_VAULT_ZERO");
        require(attestation.expiresAt >= block.timestamp, "ATTEST_EXPIRED");
    }

    function _hashRedemptionAttestation(RedemptionAttestation calldata attestation)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            _HAZAMA_REDEMPTION_ATTESTATION_TYPEHASH,
            keccak256(bytes(attestation.templateId)),
            keccak256(bytes(attestation.redemptionRequestId)),
            keccak256(bytes(attestation.assetBindingId)),
            attestation.termsHash,
            attestation.sourceChainId,
            attestation.sourceContract,
            keccak256(bytes(attestation.tokenStandard)),
            attestation.token,
            attestation.classId,
            attestation.nonceId,
            attestation.holderEvmAddress,
            keccak256(bytes(attestation.liquidNetwork)),
            keccak256(bytes(attestation.liquidTxid)),
            attestation.recoveryVout,
            keccak256(bytes(attestation.recoveryAssetId)),
            attestation.recoveryAmount,
            attestation.vaultAddressHash,
            attestation.confirmations,
            attestation.observedAt,
            attestation.expiresAt
        ));
    }

    function _tokenStandardName(IGenericRwaRedemptionRecorder.TokenStandard tokenStandard)
        private
        pure
        returns (string memory)
    {
        if (tokenStandard == IGenericRwaRedemptionRecorder.TokenStandard.ERC3475) return "ERC3475";
        if (tokenStandard == IGenericRwaRedemptionRecorder.TokenStandard.ERC20) return "ERC20";
        if (tokenStandard == IGenericRwaRedemptionRecorder.TokenStandard.ERC721) return "ERC721";
        if (tokenStandard == IGenericRwaRedemptionRecorder.TokenStandard.ERC1155) return "ERC1155";
        revert("UNSUPPORTED_STANDARD");
    }

    function _bytes32FromHexString(string calldata value) private pure returns (bytes32) {
        bytes calldata data = bytes(value);
        uint256 offset = 0;
        if (data.length == 66) {
            require(uint8(data[0]) == 48 && (uint8(data[1]) == 120 || uint8(data[1]) == 88), "HEX_PREFIX");
            offset = 2;
        } else {
            require(data.length == 64, "HEX_LENGTH");
        }

        uint256 result = 0;
        for (uint256 i = 0; i < 32; i++) {
            result = (result << 8)
                | (_hexNibble(uint8(data[offset + i * 2])) << 4)
                | _hexNibble(uint8(data[offset + i * 2 + 1]));
        }
        return bytes32(result);
    }

    function _hexNibble(uint8 char) private pure returns (uint256) {
        if (char >= 48 && char <= 57) return char - 48;
        if (char >= 65 && char <= 70) return char - 55;
        if (char >= 97 && char <= 102) return char - 87;
        revert("HEX_CHAR");
    }
}

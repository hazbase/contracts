// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

interface IGenericRwaBackingReleaseManager {
    enum TokenStandard {
        ERC3475,
        ERC20,
        ERC721,
        ERC1155
    }

    enum LockStatus {
        None,
        Locked,
        Released,
        Consumed
    }

    struct BackingLock {
        LockStatus status;
        TokenStandard tokenStandard;
        address token;
        address backingOwner;
        uint256 classId;
        uint256 nonceId;
        uint256 amount;
        bytes32 liquidAssetId;
        bytes32 termsHash;
        uint64 expiresAt;
        bytes32 liquidDeliveryTxid;
        uint64 createdAt;
        uint64 consumedAt;
    }

    function getLock(bytes32 orderId) external view returns (BackingLock memory);
    function release(bytes32 orderId, bytes32 reasonCode) external;
}

/**
 * @title HazamaRwaReleaseFinalizer
 * @notice Quorum and timeout gated release path for unconsumed EVM RWA backing.
 *
 * The backing manager grants this contract RELEASER_ROLE and revokes that role
 * from ordinary hot-wallet operators. Any caller can then submit a canonical
 * 2-of-N HAZAMA no-delivery proof after the lock timeout and release delay.
 */
contract HazamaRwaReleaseFinalizer is AccessControl, EIP712, Pausable, ReentrancyGuard {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant HAZAMA_APPROVER_ADMIN_ROLE = keccak256("HAZAMA_APPROVER_ADMIN_ROLE");
    bytes32 public constant RELEASE_TEMPLATE_HASH = keccak256("liquid-no-delivery-release-v1");

    bytes32 private constant _HAZAMA_RELEASE_ATTESTATION_TYPEHASH = keccak256(
        "HazamaReleaseAttestation(string templateId,string orderId,bytes32 orderKey,bytes32 termsHash,uint256 sourceChainId,address sourceContract,string destinationNetwork,uint64 lockExpiresAt,uint256 observedLiquidHeight,bytes32 observedLiquidBlockHash,bytes32 reasonCode,uint64 observedAt,uint64 expiresAt)"
    );

    struct ReleaseAttestation {
        string templateId;
        string orderId;
        bytes32 orderKey;
        bytes32 termsHash;
        uint256 sourceChainId;
        address sourceContract;
        string destinationNetwork;
        uint64 lockExpiresAt;
        uint256 observedLiquidHeight;
        bytes32 observedLiquidBlockHash;
        bytes32 reasonCode;
        uint64 observedAt;
        uint64 expiresAt;
    }

    IGenericRwaBackingReleaseManager public immutable backingManager;
    uint64 public immutable releaseDelaySeconds;
    mapping(address => bool) private _hazamaApprovers;
    uint256 private _hazamaApproverCount;
    uint256 private _hazamaThreshold;

    event HazamaApproverUpdated(address indexed approver, bool enabled);
    event HazamaThresholdUpdated(uint256 threshold);
    event BackingReleaseFinalized(
        bytes32 indexed orderKey,
        bytes32 indexed reasonCode,
        bytes32 indexed attestationDigest,
        address finalizer,
        uint256 signatureCount
    );

    constructor(address admin, address backingManagerAddress, uint64 releaseDelay)
        EIP712("HAZAMA Release Attestation", "1")
    {
        require(admin != address(0), "ADMIN_ZERO");
        require(backingManagerAddress != address(0), "MANAGER_ZERO");
        require(releaseDelay > 0, "RELEASE_DELAY_ZERO");
        backingManager = IGenericRwaBackingReleaseManager(backingManagerAddress);
        releaseDelaySeconds = releaseDelay;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(HAZAMA_APPROVER_ADMIN_ROLE, admin);
    }

    /**
     * @dev Callable by anyone. The timeout and approver signatures authorize
     * the release; msg.sender has no release authority of its own.
     */
    function releaseWithAttestations(
        bytes32 orderKey,
        bytes32 reasonCode,
        ReleaseAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant returns (bytes32) {
        require(orderKey != bytes32(0), "ORDER_KEY_ZERO");
        require(reasonCode != bytes32(0), "REASON_ZERO");

        IGenericRwaBackingReleaseManager.BackingLock memory entry = backingManager.getLock(orderKey);
        require(entry.status == IGenericRwaBackingReleaseManager.LockStatus.Locked, "LOCK_NOT_LOCKED");
        require(block.timestamp >= uint256(entry.expiresAt) + releaseDelaySeconds, "RELEASE_DELAY_ACTIVE");

        bytes32 digest = _verifyHazamaQuorum(orderKey, reasonCode, entry, attestations, signatures);
        backingManager.release(orderKey, reasonCode);

        emit BackingReleaseFinalized(orderKey, reasonCode, digest, msg.sender, signatures.length);
        return orderKey;
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
        bytes32 orderKey,
        bytes32 reasonCode,
        IGenericRwaBackingReleaseManager.BackingLock memory entry,
        ReleaseAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) private view returns (bytes32 firstDigest) {
        uint256 threshold = _hazamaThreshold;
        require(threshold > 0, "HAZAMA_THRESHOLD_ZERO");
        require(attestations.length == signatures.length, "HAZAMA_ATTESTATION_LENGTH");
        require(signatures.length >= threshold, "HAZAMA_QUORUM_NOT_MET");

        address[] memory accepted = new address[](signatures.length);
        uint256 count = 0;
        for (uint256 i = 0; i < signatures.length; i++) {
            _validateAttestation(orderKey, reasonCode, entry, attestations[i]);
            bytes32 digest = _hashTypedDataV4(_hashReleaseAttestation(attestations[i]));
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
    }

    function _validateAttestation(
        bytes32 orderKey,
        bytes32 reasonCode,
        IGenericRwaBackingReleaseManager.BackingLock memory entry,
        ReleaseAttestation calldata attestation
    ) private view {
        require(keccak256(bytes(attestation.templateId)) == RELEASE_TEMPLATE_HASH, "ATTEST_TEMPLATE");
        require(keccak256(bytes(attestation.orderId)) == orderKey, "ATTEST_ORDER_ID");
        require(attestation.orderKey == orderKey, "ATTEST_ORDER_KEY");
        require(attestation.termsHash == entry.termsHash, "ATTEST_TERMS_HASH");
        require(attestation.sourceChainId == block.chainid, "ATTEST_CHAIN_ID");
        require(attestation.sourceContract == address(backingManager), "ATTEST_SOURCE");
        require(bytes(attestation.destinationNetwork).length > 0, "ATTEST_NETWORK");
        require(attestation.lockExpiresAt == entry.expiresAt, "ATTEST_LOCK_EXPIRY");
        require(attestation.observedLiquidHeight > 0, "ATTEST_LIQUID_HEIGHT");
        require(attestation.observedLiquidBlockHash != bytes32(0), "ATTEST_LIQUID_BLOCK");
        require(attestation.reasonCode == reasonCode, "ATTEST_REASON");
        require(attestation.observedAt >= uint256(entry.expiresAt) + releaseDelaySeconds, "ATTEST_TOO_EARLY");
        require(attestation.observedAt <= block.timestamp + 300, "ATTEST_FUTURE");
        require(attestation.expiresAt >= block.timestamp, "ATTEST_EXPIRED");
    }

    function _hashReleaseAttestation(ReleaseAttestation calldata attestation)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            _HAZAMA_RELEASE_ATTESTATION_TYPEHASH,
            keccak256(bytes(attestation.templateId)),
            keccak256(bytes(attestation.orderId)),
            attestation.orderKey,
            attestation.termsHash,
            attestation.sourceChainId,
            attestation.sourceContract,
            keccak256(bytes(attestation.destinationNetwork)),
            attestation.lockExpiresAt,
            attestation.observedLiquidHeight,
            attestation.observedLiquidBlockHash,
            attestation.reasonCode,
            attestation.observedAt,
            attestation.expiresAt
        ));
    }
}

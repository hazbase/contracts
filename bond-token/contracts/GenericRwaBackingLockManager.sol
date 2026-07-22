// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IERC3475GenericBackingToken {
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
}

/**
 * @title GenericRwaBackingLockManager
 * @notice Order-level custody lock for EVM RWA backing across ERC-3475, ERC20, ERC721, and ERC1155 assets.
 *
 * A lock moves exact EVM backing into this contract. A released lock returns
 * the backing before Liquid delivery. A consumed lock keeps the backing in
 * custody as accounting support for the outstanding Liquid asset.
 */
contract GenericRwaBackingLockManager is
    AccessControl,
    EIP712,
    Pausable,
    ReentrancyGuard,
    IERC721Receiver,
    IERC1155Receiver
{
    using SafeERC20 for IERC20;

    bytes32 public constant LOCKER_ROLE = keccak256("LOCKER_ROLE");
    bytes32 public constant RELEASER_ROLE = keccak256("RELEASER_ROLE");
    bytes32 public constant CONSUMER_ROLE = keccak256("CONSUMER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant HAZAMA_APPROVER_ADMIN_ROLE = keccak256("HAZAMA_APPROVER_ADMIN_ROLE");

    bytes32 private constant _HAZAMA_DELIVERY_ATTESTATION_TYPEHASH = keccak256(
        "HazamaDeliveryAttestation(string templateId,string orderId,bytes32 orderKey,bytes32 termsHash,uint256 sourceChainId,address sourceContract,string destinationNetwork,string liquidTxid,uint32 paymentVout,string paymentAssetId,uint256 paymentAmount,uint32 deliveryVout,string deliveryAssetId,uint256 deliveryAmount,bytes32 deliveryAddressHash,uint256 confirmations,uint64 observedAt,uint64 expiresAt)"
    );

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

    struct BackingTotals {
        uint256 locked;
        uint256 consumed;
    }

    struct DeliveryAttestation {
        string templateId;
        string orderId;
        bytes32 orderKey;
        bytes32 termsHash;
        uint256 sourceChainId;
        address sourceContract;
        string destinationNetwork;
        string liquidTxid;
        uint32 paymentVout;
        string paymentAssetId;
        uint256 paymentAmount;
        uint32 deliveryVout;
        string deliveryAssetId;
        uint256 deliveryAmount;
        bytes32 deliveryAddressHash;
        uint256 confirmations;
        uint64 observedAt;
        uint64 expiresAt;
    }

    mapping(bytes32 => BackingLock) private _locks;
    mapping(bytes32 => BackingTotals) private _backingTotals;
    mapping(address => bool) private _hazamaApprovers;
    uint256 private _hazamaApproverCount;
    uint256 private _hazamaThreshold;

    event BackingLocked(
        bytes32 indexed orderId,
        TokenStandard indexed tokenStandard,
        address indexed token,
        address backingOwner,
        uint256 classId,
        uint256 nonceId,
        uint256 amount,
        bytes32 liquidAssetId,
        bytes32 termsHash,
        uint64 expiresAt
    );

    event BackingReleased(bytes32 indexed orderId, bytes32 reasonCode);

    event BackingConsumed(
        bytes32 indexed orderId,
        bytes32 indexed liquidDeliveryTxid
    );

    event BackingConsumedWithAttestations(
        bytes32 indexed orderId,
        bytes32 indexed liquidDeliveryTxid,
        uint256 signatureCount
    );

    event HazamaApproverUpdated(address indexed approver, bool enabled);
    event HazamaThresholdUpdated(uint256 threshold);

    constructor(address admin) EIP712("HAZAMA Delivery Attestation", "1") {
        require(admin != address(0), "ADMIN_ZERO");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(LOCKER_ROLE, admin);
        _grantRole(RELEASER_ROLE, admin);
        _grantRole(CONSUMER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
        _grantRole(HAZAMA_APPROVER_ADMIN_ROLE, admin);
    }

    function lock(
        bytes32 orderId,
        TokenStandard tokenStandard,
        address token,
        address backingOwner,
        uint256 classId,
        uint256 nonceId,
        uint256 amount,
        bytes32 liquidAssetId,
        bytes32 termsHash,
        uint64 expiresAt
    )
        external
        whenNotPaused
        nonReentrant
        onlyRole(LOCKER_ROLE)
        returns (bytes32 lockId)
    {
        require(orderId != bytes32(0), "ORDER_ID_ZERO");
        require(token != address(0), "TOKEN_ZERO");
        require(backingOwner != address(0), "OWNER_ZERO");
        require(amount > 0, "AMOUNT_ZERO");
        require(liquidAssetId != bytes32(0), "LIQUID_ASSET_ZERO");
        require(termsHash != bytes32(0), "TERMS_HASH_ZERO");
        require(expiresAt > block.timestamp, "EXPIRED");
        require(_locks[orderId].status == LockStatus.None, "LOCK_EXISTS");

        _validateStandardInput(tokenStandard, classId, nonceId, amount);
        _transferIn(tokenStandard, token, backingOwner, classId, nonceId, amount);

        _locks[orderId] = BackingLock({
            status: LockStatus.Locked,
            tokenStandard: tokenStandard,
            token: token,
            backingOwner: backingOwner,
            classId: classId,
            nonceId: nonceId,
            amount: amount,
            liquidAssetId: liquidAssetId,
            termsHash: termsHash,
            expiresAt: expiresAt,
            liquidDeliveryTxid: bytes32(0),
            createdAt: uint64(block.timestamp),
            consumedAt: 0
        });

        _backingTotals[_backingKey(tokenStandard, token, classId, nonceId)].locked += amount;

        emit BackingLocked(
            orderId,
            tokenStandard,
            token,
            backingOwner,
            classId,
            nonceId,
            amount,
            liquidAssetId,
            termsHash,
            expiresAt
        );

        return orderId;
    }

    function release(
        bytes32 orderId,
        bytes32 reasonCode
    ) external whenNotPaused nonReentrant onlyRole(RELEASER_ROLE) {
        BackingLock storage entry = _locks[orderId];
        require(entry.status == LockStatus.Locked, "LOCK_NOT_LOCKED");

        entry.status = LockStatus.Released;
        _backingTotals[_backingKey(entry.tokenStandard, entry.token, entry.classId, entry.nonceId)].locked -= entry.amount;

        _transferOut(entry.tokenStandard, entry.token, entry.backingOwner, entry.classId, entry.nonceId, entry.amount);

        emit BackingReleased(orderId, reasonCode);
    }

    function consume(
        bytes32 orderId,
        bytes32 liquidDeliveryTxid
    ) external whenNotPaused nonReentrant onlyRole(CONSUMER_ROLE) {
        require(liquidDeliveryTxid != bytes32(0), "DELIVERY_TX_ZERO");

        BackingLock storage entry = _locks[orderId];
        require(entry.status == LockStatus.Locked, "LOCK_NOT_LOCKED");

        _consume(entry, orderId, liquidDeliveryTxid);
    }

    function consumeWithAttestations(
        bytes32 orderId,
        bytes32 liquidDeliveryTxid,
        DeliveryAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) external whenNotPaused nonReentrant {
        require(liquidDeliveryTxid != bytes32(0), "DELIVERY_TX_ZERO");

        BackingLock storage entry = _locks[orderId];
        require(entry.status == LockStatus.Locked, "LOCK_NOT_LOCKED");

        _verifyHazamaQuorum(orderId, liquidDeliveryTxid, entry, attestations, signatures);
        _consume(entry, orderId, liquidDeliveryTxid);

        emit BackingConsumedWithAttestations(orderId, liquidDeliveryTxid, signatures.length);
    }

    function setHazamaApprover(address approver, bool enabled)
        external
        onlyRole(HAZAMA_APPROVER_ADMIN_ROLE)
    {
        require(approver != address(0), "APPROVER_ZERO");
        if (_hazamaApprovers[approver] == enabled) {
            return;
        }
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

    function getLock(bytes32 orderId) external view returns (BackingLock memory) {
        return _locks[orderId];
    }

    function backingBalance(
        TokenStandard tokenStandard,
        address token,
        uint256 classId,
        uint256 nonceId
    ) external view returns (uint256 locked, uint256 consumed) {
        BackingTotals storage totals = _backingTotals[_backingKey(tokenStandard, token, classId, nonceId)];
        return (totals.locked, totals.consumed);
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

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl, IERC165)
        returns (bool)
    {
        return interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC1155Receiver).interfaceId
            || super.supportsInterface(interfaceId);
    }

    function _validateStandardInput(
        TokenStandard tokenStandard,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) private pure {
        if (tokenStandard == TokenStandard.ERC20) {
            require(classId == 0 && nonceId == 0, "ERC20_ID_NONZERO");
        } else if (tokenStandard == TokenStandard.ERC721) {
            require(nonceId == 0, "ERC721_NONCE_NONZERO");
            require(amount == 1, "ERC721_AMOUNT_NOT_ONE");
        } else if (tokenStandard == TokenStandard.ERC1155) {
            require(nonceId == 0, "ERC1155_NONCE_NONZERO");
        }
    }

    function _transferIn(
        TokenStandard tokenStandard,
        address token,
        address backingOwner,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) private {
        if (tokenStandard == TokenStandard.ERC3475) {
            IERC3475GenericBackingToken(token).operatorTransferFrom(backingOwner, address(this), classId, nonceId, amount);
        } else if (tokenStandard == TokenStandard.ERC20) {
            IERC20(token).safeTransferFrom(backingOwner, address(this), amount);
        } else if (tokenStandard == TokenStandard.ERC721) {
            IERC721(token).safeTransferFrom(backingOwner, address(this), classId);
        } else if (tokenStandard == TokenStandard.ERC1155) {
            IERC1155(token).safeTransferFrom(backingOwner, address(this), classId, amount, "");
        } else {
            revert("UNSUPPORTED_STANDARD");
        }
    }

    function _transferOut(
        TokenStandard tokenStandard,
        address token,
        address backingOwner,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) private {
        if (tokenStandard == TokenStandard.ERC3475) {
            IERC3475GenericBackingToken(token).operatorTransferFrom(address(this), backingOwner, classId, nonceId, amount);
        } else if (tokenStandard == TokenStandard.ERC20) {
            IERC20(token).safeTransfer(backingOwner, amount);
        } else if (tokenStandard == TokenStandard.ERC721) {
            IERC721(token).safeTransferFrom(address(this), backingOwner, classId);
        } else if (tokenStandard == TokenStandard.ERC1155) {
            IERC1155(token).safeTransferFrom(address(this), backingOwner, classId, amount, "");
        } else {
            revert("UNSUPPORTED_STANDARD");
        }
    }

    function _consume(
        BackingLock storage entry,
        bytes32 orderId,
        bytes32 liquidDeliveryTxid
    ) private {
        entry.status = LockStatus.Consumed;
        entry.liquidDeliveryTxid = liquidDeliveryTxid;
        entry.consumedAt = uint64(block.timestamp);

        BackingTotals storage totals = _backingTotals[_backingKey(entry.tokenStandard, entry.token, entry.classId, entry.nonceId)];
        totals.locked -= entry.amount;
        totals.consumed += entry.amount;

        emit BackingConsumed(orderId, liquidDeliveryTxid);
    }

    function _validateDeliveryAttestation(
        bytes32 orderId,
        bytes32 liquidDeliveryTxid,
        BackingLock storage entry,
        DeliveryAttestation calldata attestation
    ) private view {
        require(attestation.orderKey == orderId, "ATTEST_ORDER_KEY");
        require(attestation.termsHash == entry.termsHash, "ATTEST_TERMS_HASH");
        require(attestation.sourceChainId == block.chainid, "ATTEST_CHAIN_ID");
        require(attestation.sourceContract == address(this), "ATTEST_SOURCE");
        require(_bytes32FromHexString(attestation.liquidTxid) == liquidDeliveryTxid, "ATTEST_TXID");
        require(_bytes32FromHexString(attestation.deliveryAssetId) == entry.liquidAssetId, "ATTEST_ASSET");
        require(attestation.deliveryAmount == entry.amount, "ATTEST_AMOUNT");
        require(attestation.expiresAt >= block.timestamp, "ATTEST_EXPIRED");
    }

    function _verifyHazamaQuorum(
        bytes32 orderId,
        bytes32 liquidDeliveryTxid,
        BackingLock storage entry,
        DeliveryAttestation[] calldata attestations,
        bytes[] calldata signatures
    ) private view {
        uint256 threshold = _hazamaThreshold;
        require(threshold > 0, "HAZAMA_THRESHOLD_ZERO");
        require(attestations.length == signatures.length, "HAZAMA_ATTESTATION_LENGTH");
        require(signatures.length >= threshold, "HAZAMA_QUORUM_NOT_MET");

        address[] memory accepted = new address[](signatures.length);
        uint256 count = 0;

        for (uint256 i = 0; i < signatures.length; i++) {
            _validateDeliveryAttestation(orderId, liquidDeliveryTxid, entry, attestations[i]);
            bytes32 digest = _hashTypedDataV4(_hashDeliveryAttestation(attestations[i]));
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

    function _hashDeliveryAttestation(DeliveryAttestation calldata attestation)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(
            _HAZAMA_DELIVERY_ATTESTATION_TYPEHASH,
            keccak256(bytes(attestation.templateId)),
            keccak256(bytes(attestation.orderId)),
            attestation.orderKey,
            attestation.termsHash,
            attestation.sourceChainId,
            attestation.sourceContract,
            keccak256(bytes(attestation.destinationNetwork)),
            keccak256(bytes(attestation.liquidTxid)),
            attestation.paymentVout,
            keccak256(bytes(attestation.paymentAssetId)),
            attestation.paymentAmount,
            attestation.deliveryVout,
            keccak256(bytes(attestation.deliveryAssetId)),
            attestation.deliveryAmount,
            attestation.deliveryAddressHash,
            attestation.confirmations,
            attestation.observedAt,
            attestation.expiresAt
        ));
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

    function _backingKey(
        TokenStandard tokenStandard,
        address token,
        uint256 classId,
        uint256 nonceId
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(tokenStandard, token, classId, nonceId));
    }
}

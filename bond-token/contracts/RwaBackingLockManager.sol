// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IERC3475BackingToken {
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
}

/**
 * @title RwaBackingLockManager
 * @notice Order-level custody lock for EVM RWA backing used by Liquid settlement flows.
 *
 * A lock moves exact BondToken units from the backing owner into this contract.
 * A released lock returns units before Liquid delivery. A consumed lock keeps
 * the units in this contract as backing for the outstanding Liquid asset.
 */
contract RwaBackingLockManager is AccessControl, Pausable, ReentrancyGuard {
    bytes32 public constant LOCKER_ROLE = keccak256("LOCKER_ROLE");
    bytes32 public constant RELEASER_ROLE = keccak256("RELEASER_ROLE");
    bytes32 public constant CONSUMER_ROLE = keccak256("CONSUMER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    enum LockStatus {
        None,
        Locked,
        Released,
        Consumed
    }

    struct BackingLock {
        LockStatus status;
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

    mapping(bytes32 => BackingLock) private _locks;
    mapping(bytes32 => BackingTotals) private _backingTotals;

    event BackingLocked(
        bytes32 indexed orderId,
        address indexed token,
        address indexed backingOwner,
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

    constructor(address admin) {
        require(admin != address(0), "ADMIN_ZERO");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(LOCKER_ROLE, admin);
        _grantRole(RELEASER_ROLE, admin);
        _grantRole(CONSUMER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    function lock(
        bytes32 orderId,
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

        IERC3475BackingToken(token).operatorTransferFrom(
            backingOwner,
            address(this),
            classId,
            nonceId,
            amount
        );

        _locks[orderId] = BackingLock({
            status: LockStatus.Locked,
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

        _backingTotals[_backingKey(token, classId, nonceId)].locked += amount;

        emit BackingLocked(
            orderId,
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
        _backingTotals[_backingKey(entry.token, entry.classId, entry.nonceId)].locked -= entry.amount;

        IERC3475BackingToken(entry.token).operatorTransferFrom(
            address(this),
            entry.backingOwner,
            entry.classId,
            entry.nonceId,
            entry.amount
        );

        emit BackingReleased(orderId, reasonCode);
    }

    function consume(
        bytes32 orderId,
        bytes32 liquidDeliveryTxid
    ) external whenNotPaused nonReentrant onlyRole(CONSUMER_ROLE) {
        require(liquidDeliveryTxid != bytes32(0), "DELIVERY_TX_ZERO");

        BackingLock storage entry = _locks[orderId];
        require(entry.status == LockStatus.Locked, "LOCK_NOT_LOCKED");

        entry.status = LockStatus.Consumed;
        entry.liquidDeliveryTxid = liquidDeliveryTxid;
        entry.consumedAt = uint64(block.timestamp);

        BackingTotals storage totals = _backingTotals[_backingKey(entry.token, entry.classId, entry.nonceId)];
        totals.locked -= entry.amount;
        totals.consumed += entry.amount;

        emit BackingConsumed(orderId, liquidDeliveryTxid);
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
        address token,
        uint256 classId,
        uint256 nonceId
    ) external view returns (uint256 locked, uint256 consumed) {
        BackingTotals storage totals = _backingTotals[_backingKey(token, classId, nonceId)];
        return (totals.locked, totals.consumed);
    }

    function _backingKey(
        address token,
        uint256 classId,
        uint256 nonceId
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(token, classId, nonceId));
    }
}

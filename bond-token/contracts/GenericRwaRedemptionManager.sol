// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title GenericRwaRedemptionManager
 * @notice Append-only redemption ledger for Liquid-delivered RWA assets backed by EVM source assets.
 *
 * The contract records that a specific Liquid recovery output has been accepted
 * for physical redemption and binds it to the EVM asset identity. It does not
 * custody, burn, or transfer the source EVM asset; purchase-time backing custody
 * remains handled by GenericRwaBackingLockManager.
 */
contract GenericRwaRedemptionManager is AccessControl, Pausable, ReentrancyGuard {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    enum TokenStandard {
        ERC3475,
        ERC20,
        ERC721,
        ERC1155
    }

    enum RedemptionStatus {
        None,
        Recorded
    }

    struct RedemptionRecord {
        RedemptionStatus status;
        TokenStandard tokenStandard;
        address token;
        address holder;
        uint256 classId;
        uint256 nonceId;
        uint256 amount;
        bytes32 liquidAssetId;
        bytes32 liquidRecoveryTxid;
        uint32 liquidRecoveryVout;
        bytes32 termsHash;
        bytes32 evidenceHash;
        uint64 recordedAt;
    }

    struct RedemptionTotals {
        uint256 redeemed;
    }

    mapping(bytes32 => RedemptionRecord) private _redemptions;
    mapping(bytes32 => RedemptionTotals) private _redemptionTotals;
    mapping(bytes32 => bool) private _usedLiquidRecoveryOutputs;

    event RwaRedeemed(
        bytes32 indexed redemptionId,
        TokenStandard indexed tokenStandard,
        address indexed token,
        address holder,
        uint256 classId,
        uint256 nonceId,
        uint256 amount,
        bytes32 liquidAssetId,
        bytes32 liquidRecoveryTxid,
        uint32 liquidRecoveryVout,
        bytes32 termsHash,
        bytes32 evidenceHash
    );

    constructor(address admin) {
        require(admin != address(0), "ADMIN_ZERO");
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(RECORDER_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
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
    ) external whenNotPaused nonReentrant onlyRole(RECORDER_ROLE) returns (bytes32) {
        require(redemptionId != bytes32(0), "REDEMPTION_ID_ZERO");
        require(token != address(0), "TOKEN_ZERO");
        require(holder != address(0), "HOLDER_ZERO");
        require(amount > 0, "AMOUNT_ZERO");
        require(liquidAssetId != bytes32(0), "LIQUID_ASSET_ZERO");
        require(liquidRecoveryTxid != bytes32(0), "RECOVERY_TX_ZERO");
        require(termsHash != bytes32(0), "TERMS_HASH_ZERO");
        require(evidenceHash != bytes32(0), "EVIDENCE_HASH_ZERO");
        require(_redemptions[redemptionId].status == RedemptionStatus.None, "REDEMPTION_EXISTS");

        _validateStandardInput(tokenStandard, classId, nonceId, amount);

        bytes32 recoveryOutputKey = _liquidRecoveryOutputKey(liquidRecoveryTxid, liquidRecoveryVout);
        require(!_usedLiquidRecoveryOutputs[recoveryOutputKey], "RECOVERY_OUTPUT_USED");
        _usedLiquidRecoveryOutputs[recoveryOutputKey] = true;

        _redemptions[redemptionId] = RedemptionRecord({
            status: RedemptionStatus.Recorded,
            tokenStandard: tokenStandard,
            token: token,
            holder: holder,
            classId: classId,
            nonceId: nonceId,
            amount: amount,
            liquidAssetId: liquidAssetId,
            liquidRecoveryTxid: liquidRecoveryTxid,
            liquidRecoveryVout: liquidRecoveryVout,
            termsHash: termsHash,
            evidenceHash: evidenceHash,
            recordedAt: uint64(block.timestamp)
        });

        _redemptionTotals[_assetKey(tokenStandard, token, classId, nonceId)].redeemed += amount;

        emit RwaRedeemed(
            redemptionId,
            tokenStandard,
            token,
            holder,
            classId,
            nonceId,
            amount,
            liquidAssetId,
            liquidRecoveryTxid,
            liquidRecoveryVout,
            termsHash,
            evidenceHash
        );

        return redemptionId;
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function getRedemption(bytes32 redemptionId) external view returns (RedemptionRecord memory) {
        return _redemptions[redemptionId];
    }

    function redemptionBalance(
        TokenStandard tokenStandard,
        address token,
        uint256 classId,
        uint256 nonceId
    ) external view returns (uint256 redeemed) {
        return _redemptionTotals[_assetKey(tokenStandard, token, classId, nonceId)].redeemed;
    }

    function isLiquidRecoveryOutputUsed(bytes32 liquidRecoveryTxid, uint32 liquidRecoveryVout)
        external
        view
        returns (bool)
    {
        return _usedLiquidRecoveryOutputs[_liquidRecoveryOutputKey(liquidRecoveryTxid, liquidRecoveryVout)];
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

    function _assetKey(
        TokenStandard tokenStandard,
        address token,
        uint256 classId,
        uint256 nonceId
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(tokenStandard, token, classId, nonceId));
    }

    function _liquidRecoveryOutputKey(bytes32 liquidRecoveryTxid, uint32 liquidRecoveryVout)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(liquidRecoveryTxid, liquidRecoveryVout));
    }
}

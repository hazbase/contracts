// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

interface IPhysicalAssetTransferPolicy {
    function isWhitelisted(address account) external view returns (bool);
}

/**
 * @title PhysicalAssetToken
 * @notice One immutable ERC-721 right per off-chain physical item.
 *
 * Raw serial numbers, custody locations, personal data, and delivery details must
 * remain off-chain. The contract stores only salted commitments and document
 * digests so an authorized party can later prove which item and legal terms were
 * bound to a token without publishing the source records.
 *
 * The implementation is intended to be cloned once per issuer tenant through
 * the existing ContractFactory. It is deliberately not upgradeable after clone
 * deployment; a replacement collection requires an explicit migration.
 */
contract PhysicalAssetToken is
    Initializable,
    ERC721Upgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant ASSET_GUARDIAN_ROLE = keccak256("ASSET_GUARDIAN_ROLE");
    bytes32 public constant REDEEMER_ROLE = keccak256("REDEEMER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    enum AssetStatus {
        None,
        Active,
        Frozen,
        Redeemed
    }

    struct AssetRecord {
        bytes32 assetCommitment;
        bytes32 rightsHash;
        bytes32 metadataHash;
        AssetStatus status;
        bytes32 redemptionId;
        bytes32 fulfillmentEvidenceHash;
        uint64 issuedAt;
        uint64 redeemedAt;
    }

    bytes32 public tenantKey;
    IPhysicalAssetTransferPolicy public transferPolicy;
    string private _baseTokenUri;

    mapping(uint256 => AssetRecord) private _assetRecords;
    mapping(bytes32 => uint256) private _tokenByCommitment;
    mapping(bytes32 => bool) private _knownCommitments;

    event PhysicalAssetIssued(
        uint256 indexed tokenId,
        bytes32 indexed assetCommitment,
        address indexed recipient,
        bytes32 rightsHash,
        bytes32 metadataHash
    );
    event PhysicalAssetFrozen(uint256 indexed tokenId, bytes32 indexed reasonHash);
    event PhysicalAssetUnfrozen(uint256 indexed tokenId);
    event PhysicalAssetRedeemed(
        uint256 indexed tokenId,
        bytes32 indexed redemptionId,
        bytes32 indexed fulfillmentEvidenceHash
    );

    error AddressZero();
    error CommitmentZero();
    error DigestZero();
    error TenantKeyZero();
    error CommitmentAlreadyIssued();
    error TokenAlreadyIssued();
    error AssetNotActive();
    error AssetNotFrozen();
    error TransferNotAllowed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        string calldata baseTokenUri,
        bytes32 tenantKey_,
        address admin,
        address issuer,
        address assetGuardian,
        address redeemer,
        address transferPolicy_
    ) external initializer {
        if (admin == address(0) || issuer == address(0) || assetGuardian == address(0) || redeemer == address(0)) {
            revert AddressZero();
        }
        if (tenantKey_ == bytes32(0)) revert TenantKeyZero();

        __ERC721_init(name, symbol);
        __AccessControl_init();
        __Pausable_init();
        __ReentrancyGuard_init();

        tenantKey = tenantKey_;
        transferPolicy = IPhysicalAssetTransferPolicy(transferPolicy_);
        _baseTokenUri = baseTokenUri;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ISSUER_ROLE, issuer);
        _grantRole(ASSET_GUARDIAN_ROLE, assetGuardian);
        _grantRole(REDEEMER_ROLE, redeemer);
        _grantRole(PAUSER_ROLE, admin);
    }

    function issue(
        address recipient,
        bytes32 assetCommitment,
        bytes32 rightsHash,
        bytes32 metadataHash
    ) external onlyRole(ISSUER_ROLE) whenNotPaused nonReentrant returns (uint256 tokenId) {
        if (recipient == address(0)) revert AddressZero();
        if (assetCommitment == bytes32(0)) revert CommitmentZero();
        if (rightsHash == bytes32(0) || metadataHash == bytes32(0)) revert DigestZero();
        if (_knownCommitments[assetCommitment]) revert CommitmentAlreadyIssued();

        tokenId = uint256(assetCommitment);
        if (tokenId == 0) revert CommitmentZero();
        if (_assetRecords[tokenId].status != AssetStatus.None || _ownerOf(tokenId) != address(0)) {
            revert TokenAlreadyIssued();
        }

        _knownCommitments[assetCommitment] = true;
        _tokenByCommitment[assetCommitment] = tokenId;
        _assetRecords[tokenId] = AssetRecord({
            assetCommitment: assetCommitment,
            rightsHash: rightsHash,
            metadataHash: metadataHash,
            status: AssetStatus.Active,
            redemptionId: bytes32(0),
            fulfillmentEvidenceHash: bytes32(0),
            issuedAt: uint64(block.timestamp),
            redeemedAt: 0
        });

        // The approved hazBase custody account is a contract account and does
        // not currently expose IERC721Receiver. The issuer role and RWA Ops
        // binding constrain the recipient, so mint without a receiver callback.
        _mint(recipient, tokenId);
        emit PhysicalAssetIssued(tokenId, assetCommitment, recipient, rightsHash, metadataHash);
    }

    function freeze(uint256 tokenId, bytes32 reasonHash)
        external
        onlyRole(ASSET_GUARDIAN_ROLE)
        whenNotPaused
    {
        AssetRecord storage record = _assetRecords[tokenId];
        if (record.status != AssetStatus.Active) revert AssetNotActive();
        if (reasonHash == bytes32(0)) revert DigestZero();
        record.status = AssetStatus.Frozen;
        emit PhysicalAssetFrozen(tokenId, reasonHash);
    }

    function unfreeze(uint256 tokenId)
        external
        onlyRole(ASSET_GUARDIAN_ROLE)
        whenNotPaused
    {
        AssetRecord storage record = _assetRecords[tokenId];
        if (record.status != AssetStatus.Frozen) revert AssetNotFrozen();
        record.status = AssetStatus.Active;
        emit PhysicalAssetUnfrozen(tokenId);
    }

    /**
     * @notice Permanently consumes a right after the corresponding physical
     * item has been delivered and the fulfillment evidence has been approved.
     */
    function redeem(
        uint256 tokenId,
        bytes32 redemptionId,
        bytes32 fulfillmentEvidenceHash
    ) external onlyRole(REDEEMER_ROLE) whenNotPaused nonReentrant {
        AssetRecord storage record = _assetRecords[tokenId];
        if (record.status != AssetStatus.Active && record.status != AssetStatus.Frozen) revert AssetNotActive();
        if (redemptionId == bytes32(0) || fulfillmentEvidenceHash == bytes32(0)) revert DigestZero();

        record.status = AssetStatus.Redeemed;
        record.redemptionId = redemptionId;
        record.fulfillmentEvidenceHash = fulfillmentEvidenceHash;
        record.redeemedAt = uint64(block.timestamp);
        _burn(tokenId);

        emit PhysicalAssetRedeemed(tokenId, redemptionId, fulfillmentEvidenceHash);
    }

    function assetRecord(uint256 tokenId) external view returns (AssetRecord memory) {
        return _assetRecords[tokenId];
    }

    function tokenForCommitment(bytes32 assetCommitment)
        external
        view
        returns (uint256 tokenId, bool issued)
    {
        return (_tokenByCommitment[assetCommitment], _knownCommitments[assetCommitment]);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _baseURI() internal view override returns (string memory) {
        return _baseTokenUri;
    }

    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address from)
    {
        _requireNotPaused();
        from = _ownerOf(tokenId);
        if (from != address(0) && to != address(0)) {
            if (_assetRecords[tokenId].status != AssetStatus.Active) revert AssetNotActive();
            // Transfers fail closed. A tenant that has not configured an
            // approved-account policy can issue and redeem rights, but cannot
            // move them to an unintended account.
            if (
                address(transferPolicy) == address(0)
                    || !transferPolicy.isWhitelisted(from)
                    || !transferPolicy.isWhitelisted(to)
            ) {
                revert TransferNotAllowed();
            }
        }
        return super._update(to, tokenId, auth);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//   https://hazbase.com

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ------ ERC-1400 minimal ------
 * @dev Partitioned security token (subset). Only the methods used by this contract are declared.
 */
interface IERC1400 {
    /**
     * @notice Transfer by partition (escrow/settlement path for ERC-1400).
     * @param partition  Partition identifier (bytes32).
     * @param to         Recipient address.
     * @param value      Amount of tokens to transfer within the partition.
     * @param data       Optional data (unused here; pass empty bytes).
     */
    function transferByPartition(
        bytes32 partition,
        address to,
        uint256 value,
        bytes calldata data
    ) external;

    /**
     * @notice Read balance for a holder under a given partition.
     * @param partition    Partition identifier.
     * @param tokenHolder  Account to query.
     * @return balance     Partitioned balance.
     */
    function balanceOfByPartition(
        bytes32 partition,
        address tokenHolder
    ) external view returns (uint256);
}

/* ------ ERC-3475 / BondToken minimal ------
 * @dev Class/Nonce-based bond token (subset). Only the methods used by this contract are declared.
 */
interface IERC3475 {
    struct Values { string key; string value; }
    struct ClassData { Values[] data; }
    struct NonceData { Values[] data; }

    event ClassCreated(uint256 indexed classId);
    event NonceCreated(uint256 indexed classId, uint256 indexed nonceId);
    event Transfer(address indexed from, address indexed to,
                   uint256 indexed classId, uint256 nonceId, uint256 amount);
    event Redeemed(address indexed from,
                   uint256 indexed classId, uint256 indexed nonceId, uint256 amount);

    /**
     * @notice Issue (mint) bonds to `to` (not used by this contract).
     */
    function issue(address to, uint256 classId,
                   uint256 nonceId, uint256 amount) external;

    /**
     * @notice Transfer bond units (msg.sender scope).
     */
    function transfer(address to, uint256 classId,
                      uint256 nonceId, uint256 amount) external;

    /**
     * @notice Redeem (burn) bonds (not used by this contract).
     */
    function redeem(uint256 classId, uint256 nonceId, uint256 amount) external;

    /**
     * @notice Balance query for a specific class/nonce.
     */
    function balanceOf(address owner, uint256 classId,
                       uint256 nonceId) external view returns (uint256);

    /**
     * @notice Operator transfer used for escrow/settlement (contract must be authorized as operator).
     * @param from     Source address.
     * @param to       Destination address.
     * @param classId  Bond class identifier.
     * @param nonceId  Bond nonce identifier.
     * @param amount   Units to transfer.
     */
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
}

/**
 * @dev Safe ERC165 helper.
 * - Returns false for EOAs or if supportsInterface call fails/returns malformed data.
 */
library SafeERC165 {
    /**
     * @notice Safely check ERC165 `supportsInterface`.
     * @param target  Address of the contract to probe.
     * @param iid     Interface id.
     * @return bool   True if `target` is a contract and claims to support `iid`.
     */
    function safeSupportsInterface(address target, bytes4 iid) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(target) }
        if (size == 0) return false;              // EOA

        (bool ok, bytes memory data) = target.staticcall(
            abi.encodeWithSelector(IERC165.supportsInterface.selector, iid)
        );
        if (!ok || data.length < 32) return false;
        return abi.decode(data, (bool));
    }
}

/*
 *  @title AgreementManager
 *
 *  @notice
 *  - Purpose: Two-step bilateral agreement manager with optional escrow for multiple token standards.
 *  - Escrowable assets: ERC20, ERC721, ERC1155, ERC1400 (partitioned), ERC3475 (bond/class+nonce).
 *  - Flow:
 *      1) issuer calls `offer(...)` with an EIP-712 signature from the issuer (self-signed).
 *         Optionally escrows assets into this contract (if tokenAddress != address(0)).
 *      2) investor (or delegated market) calls `acceptOffer(offerId, investorSig)` with an
 *         EIP-712 signature from the investor, transferring the escrowed asset to the investor.
 *      3) investor may `rejectOffer(...)` to return escrow to issuer; issuer may `cancelOffer(...)`.
 *  - Meta-transactions: ERC-2771 trusted forwarders are supported via ERC2771Context.
 *  - Upgradeability: UUPS upgradeable, access-controlled via ADMIN_ROLE.
 *  - Pausing: PAUSER_ROLE can pause/unpause state-changing entrypoints.
 *  - Reentrancy: State-changing external functions are guarded by ReentrancyGuard.
 *
 *  @dev SECURITY / AUDIT NOTES
 *  - EIP-712 domain: name="AgreementManager", version="1". Changing these breaks signature domain.
 *  - Nonce handling: `usedNonces[issuer][nonce]` prevents replay per issuer; `currentNonce[issuer]` is informational.
 *  - Escrowless mode: When tokenAddress == address(0), no asset moves (pure agreement record). Parameters must be zeroed.
 *  - Interface detection: Uses `SafeERC165.safeSupportsInterface` to detect ERC165-based standards.
 *    Falls back to ERC20 if no known interface matches.
 *  - External calls: Token transfers occur during escrow/settlement; guarded by nonReentrant and Pausable.
 *  - Offer lifecycle: mapping `offers` stores transient state; on settle/cancel/reject, the record is deleted and a cleanup event emitted.
 *  - Disputes: Lightweight registry; no automatic enforcement, only status tracking by GUARDIAN_ROLE.
 *  - Trust assumptions: Issuer must have granted approvals for escrow; ERC3475 requires operator permission.
 *  - DoS surface: Large/invalid tokens could revert in escrow/transfer paths; caller pays gas.
 *  - Upgrades: `_authorizeUpgrade` restricted to ADMIN_ROLE; storage gap reserved.
 */

contract AgreementManager is
    Initializable,
    ERC2771ContextUpgradeable,
    ERC721Holder,
    ERC1155Holder,
    EIP712Upgradeable,
    ReentrancyGuardUpgradeable,
    RolesCommonUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;
    using SafeERC165 for address;
    using ECDSA for bytes32;

    /*────────────────────── Types & Storage ──────────────────────*/

    /**
     * @dev Offer lifecycle states.
     * None -> Offered -> (Accepted | Rejected | Cancelled)
     */
    enum OfferStatus {
        None,
        Offered,
        Accepted,
        Rejected,
        Cancelled
    }

    /// @dev EIP-712 typed data hash for Offer data structure (issuer/investor both sign over the same struct).
    bytes32 private constant OFFER_TYPEHASH =
        keccak256(
            "Offer(address issuer,address investor,address tokenAddress,bytes32 partition,uint256 tokenId,uint256 amount,uint256 classId,uint256 nonceId,bytes32 documentHash,string documentURI,uint256 expiry,uint256 nonce)"
        );

    /**
     * @dev Canonical offer struct persisted in storage until finalization.
     * - `delegatedTo` allows a market/agent to call `acceptOffer` on behalf of `investor`.
     * - `issuerSig` is stored; `investorSig` is provided at acceptance time (emitted in event).
     */
    struct Offer {
        address issuer;        // Offer maker (escrows asset from this address)
        address investor;      // Intended counterparty
        address tokenAddress;  // Asset contract address; address(0) => escrowless agreement
        bytes32 partition;     // ERC-1400 partition (ignored for other standards)
        uint256 tokenId;       // ERC721/1155 id (0 for fungibles / ERC20/1400/3475)
        uint256 classId;       // ERC-3475 class (0 for others)
        uint256 nonceId;       // ERC-3475 nonce  (0 for others)
        uint256 amount;        // ERC20/1400/1155/3475 quantity (1 for single ERC721)
        bytes32 documentHash;  // Off-chain document hash (e.g., keccak256 of docs)
        string  documentURI;   // Off-chain document URI (IPFS/HTTPS)
        uint256 expiry;        // UNIX timestamp; offer invalid after this time
        uint256 nonce;         // Per-issuer nonce to prevent replay
        address delegatedTo;   // If nonzero, only this address can `acceptOffer`
        bytes   issuerSig;     // EIP-712 signature by issuer (over OFFER_TYPEHASH fields)
        OfferStatus status;    // Lifecycle status
    }

    /// @notice offerId (bytes32) => Offer data
    mapping(bytes32 => Offer) public offers;

    /// @notice Replay protection: issuer => nonce => used?
    mapping(address => mapping(uint256 => bool)) public usedNonces;

    /// @notice Informational: `nextNonce(issuer)` reads this.
    mapping(address => uint256) public  currentNonce;       // issuer => next nonce

    /// @notice Settlement flag for an offerId (true after successful acceptance)
    mapping(bytes32 => bool) public isSettled;

    /// @notice Emitted when a new offer is created and escrow operation (if any) succeeded.
    event OfferCreated(bytes32 indexed offerId, address indexed issuer, address indexed investor);

    /// @notice Emitted when an offer is cancelled by issuer (escrow returned to issuer).
    event OfferCancelled(bytes32 indexed offerId);

    /// @notice Emitted when an offer is accepted (escrow transferred to investor).
    /// @dev Includes both issuerSig (stored) and investorSig (provided at call).
    event OfferSettled(bytes32 indexed offerId,address indexed issuer,address indexed investor,address tokenAddress,bytes32 partition,uint256 tokenId,uint256 classId,uint256 nonceId,uint256 amount,bytes32 documentHash,string documentURI,uint256 expiry,uint256 nonce,bytes issuerSig,bytes investorSig);

    /// @notice Emitted when an offer is rejected by the investor (escrow returned to issuer).
    event OfferRejected(bytes32 indexed offerId);

    /// @notice Emitted after deleting the offer struct from storage (post-finalization cleanup).
    event OfferCleanedUp(bytes32 indexed offerId);

    /// @dev Dispute lifecycle states; purely administrative (no automatic fund movement).
    enum DisputeStatus { None, Raised, Acknowledged, Resolved, Rejected }

    /// @dev Minimal dispute record.
    struct Dispute {
        address claimant;      // Sender who raised the dispute
        bytes32 offerId;       // Optional link to an offerId (0x0 if unrelated)
        string  evidenceURI;   // Evidence pointer (IPFS/HTTPS)
        DisputeStatus status;  // Current status
        uint64  createdAt;     // Timestamp (seconds)
    }

    /// @notice disputeId => Dispute data
    mapping(bytes32 => Dispute) private _disputes;

    /// @notice Dispute created.
    event DisputeRaised(
        bytes32 indexed disputeId,
        bytes32 indexed offerId,
        address indexed claimant,
        string  evidenceURI
    );

    /// @notice Dispute status transition by guardian.
    event DisputeStatusChanged(bytes32 indexed disputeId, DisputeStatus newStatus);

    /// @dev EIP-712 domain data
    string private constant CONTRACT_TYPE = "AgreementManager";
    string private constant VERSION       = "1";

    /*────────────────────── Initializer ──────────────────────────*/

    /**
     * @notice Disable initializers in constructor (UUPS pattern).
     */
    constructor() { _disableInitializers(); }

    /**
     * @notice Initialize proxy instance.
     * @param admin       Address to be granted ADMIN/PAUSER/GUARDIAN roles via RolesCommon.
     * @param forwarders  Trusted forwarder list for ERC-2771 meta-transactions.
     *
     * @dev Calls initializers of inherited upgradeable modules.
     */
    function initialize(address admin, address[] calldata forwarders) external initializer {
        __ERC2771Context_init(forwarders);
        __EIP712_init(CONTRACT_TYPE, VERSION);
        __RolesCommon_init(admin);
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
    }

    /*────────────────────── Public views ─────────────────────────*/

    /**
     * @notice EIP-712 domain name.
     * @return string  Constant "AgreementManager".
     */
    function contractType() external pure returns (string memory) {
        return CONTRACT_TYPE;
    }

    /**
     * @notice EIP-712 domain version.
     * @return string  Constant "1".
     */
    function contractVersion() external pure returns (string memory) {
        return VERSION;
    }

    /**
     * @notice Read the next nonce for an issuer (informational).
     * @param issuer  Address of the issuer.
     * @return uint256 Next nonce value expected to be unused.
     */
    function nextNonce(address issuer) external view returns (uint256) {
        return currentNonce[issuer];
    }

    /*────────────────────── Core: offer flow ─────────────────────*/

    /**
     * @notice Create an offer and optionally escrow assets into the contract.
     *
     * @param investor      The intended counterparty who may accept/reject the offer.
     * @param tokenAddress  Asset contract address; `address(0)` means escrowless (no asset moved).
     * @param partition     ERC-1400 partition (ignored for other standards).
     * @param tokenId       ERC721/1155 token id (0 for fungibles).
     * @param amount        Quantity for ERC20/1400/1155/3475 (1 for single ERC721).
     * @param classId       ERC-3475 class id (0 for others).
     * @param nonceId       ERC-3475 nonce id (0 for others).
     * @param documentHash  Hash of off-chain document describing the agreement.
     * @param documentURI   URI pointing to the off-chain document (IPFS/HTTPS).
     * @param expiry        UNIX timestamp when the offer expires (must be >= block.timestamp).
     * @param nonce         Issuer-scoped nonce for replay protection (must be unused).
     * @param issuerSig     EIP-712 signature by the issuer over OFFER_TYPEHASH with the above fields.
     * @param market        Optional delegated executor; if nonzero, only this address can call `acceptOffer`.
     *
     * @dev
     * - Effects:
     *   * Validates expiry and per-issuer nonce.
     *   * Verifies issuer EIP-712 signature.
     *   * Escrows assets from `msg.sender` (issuer) unless `tokenAddress == address(0)`.
     *   * Stores Offer struct in `offers` keyed by deterministic `offerId`.
     *   * Marks `usedNonces[issuer][nonce] = true` and increments `currentNonce[issuer]`.
     * - Interactions:
     *   * External token calls for escrow (`_escrow`).
     * - Emits: `OfferCreated(offerId, issuer, investor)`.
     *
     * @custom:reverts
     * - "Offer expired" if `block.timestamp > expiry`
     * - "Nonce used" if `usedNonces[issuer][nonce] == true`
     * - "escrowless params" if escrowless but any of {tokenId, amount, classId, nonceId} != 0
     * - "Bad issuer sig" if EIP-712 signature verification fails
     * - "Offer exists" if computed `offerId` already used
     */
    function offer(
        address investor,
        address tokenAddress,
        bytes32 partition,
        uint256 tokenId,
        uint256 amount,
        uint256 classId,
        uint256 nonceId,
        bytes32 documentHash,
        string calldata documentURI,
        uint256 expiry,
        uint256 nonce,
        bytes calldata issuerSig,
        address market
    ) external whenNotPaused nonReentrant {
        address issuer = _msgSender();
        require(block.timestamp <= expiry, "Offer expired");
        require(!usedNonces[issuer][nonce], "Nonce used");
        if (tokenAddress == address(0)) {
            require(amount == 0 && tokenId == 0, "escrowless params");
        }

        /* ── verify EIP-712 signature ── */
        bytes32 structHash = keccak256(
            abi.encode(
                OFFER_TYPEHASH,
                issuer,
                investor,
                tokenAddress,
                partition,
                tokenId,
                amount,
                classId,
                nonceId,
                documentHash,
                keccak256(bytes(documentURI)),
                expiry,
                nonce
            )
        );
        require(
            _hashTypedDataV4(structHash).recover(issuerSig) == issuer,
            "Bad issuer sig"
        );

        usedNonces[issuer][nonce] = true;
        currentNonce[issuer]++;

        // @dev Deterministic offer id; independent of `delegatedTo` and investorSig.
        bytes32 offerId = keccak256(abi.encode(
            bytes1(0x01),
            issuer,
            bytes1(0x02),
            investor,
            bytes1(0x03),
            tokenAddress,
            partition,
            tokenId,
            amount,
            classId,
            nonceId,
            documentHash,
            keccak256(bytes(documentURI)),
            expiry,
            nonce
        ));
        Offer storage o = offers[offerId];
        require(o.status == OfferStatus.None, "Offer exists");

        /* ── escrow ── */
        _escrow(tokenAddress, partition, tokenId, amount, classId, nonceId);

        /* ── fill struct ── */
        o.issuer   = issuer;
        o.investor = investor;
        o.tokenAddress = tokenAddress;
        o.partition    = partition;
        o.tokenId      = tokenId;
        o.amount       = amount;
        o.classId      = classId;
        o.nonceId      = nonceId;
        o.documentHash = documentHash;
        o.documentURI  = documentURI;
        o.expiry       = expiry;
        o.nonce        = nonce;
        o.issuerSig    = issuerSig;
        o.delegatedTo  = market;
        o.status       = OfferStatus.Offered;

        emit OfferCreated(offerId, issuer, investor);
    }

    /**
     * @notice Cancel an offered (non-expired) offer; only issuer can cancel.
     *         Escrowed assets are returned to issuer and the offer record is deleted.
     *
     * @param offerId  The id returned/emitted at `offer(...)`.
     *
     * @dev
     * - Requirements:
     *   * `offers[offerId].status == Offered`
     *   * `msg.sender == offers[offerId].issuer`
     * - Effects:
     *   * Status set to Cancelled, escrow returned to issuer.
     *   * Offer storage entry deleted and cleanup event emitted.
     * - Emits: `OfferCancelled(offerId)`, `OfferCleanedUp(offerId)`.
     *
     * @custom:reverts
     * - "Not offered" if `status != Offered`
     * - "Not issuer" if caller is not the issuer
     */
    function cancelOffer(bytes32 offerId) external whenNotPaused nonReentrant {
        Offer storage o = offers[offerId];
        require(o.status == OfferStatus.Offered, "Not offered");
        require(_msgSender() == o.issuer,        "Not issuer");

        o.status = OfferStatus.Cancelled;
        _transfer(o.issuer, o);

        emit OfferCancelled(offerId);
        delete offers[offerId];
        emit OfferCleanedUp(offerId);
    }

    /**
     * @notice Accept an existing offer either by the investor or by a delegated market.
     *         Transfers escrowed assets to the investor and finalizes the offer.
     *
     * @param offerId      Deterministic id of the offer computed in `offer(...)`.
     * @param investorSig  EIP-712 signature by the investor over the same struct as issuer signed.
     *
     * @dev
     * - Caller:
     *   * If `offers[offerId].delegatedTo != 0`, caller must equal `delegatedTo` and investor must be `offers[offerId].investor`.
     *   * Otherwise caller must be exactly `offers[offerId].investor`.
     * - Requirements:
     *   * `status == Offered`
     *   * `block.timestamp <= expiry`
     *   * `investorSig` must recover to `offers[offerId].investor`.
     * - Effects:
     *   * Status set to Accepted, escrow transferred to investor, `isSettled[offerId] = true`.
     *   * Offer storage entry deleted and cleanup event emitted.
     * - Emits: `OfferSettled(...)`, `OfferCleanedUp(offerId)`.
     *
     * @custom:reverts
     * - "not offered" if not in Offered state
     * - "expired" if now > expiry
     * - "delegated:auth" if improper delegated caller
     * - "wrong investor" if caller is not the designated investor (no delegation)
     * - "bad sig" if `investorSig` fails EIP-712 verification
     */
    function acceptOffer(bytes32 offerId, bytes calldata investorSig)
        external
        whenNotPaused
        nonReentrant
    {
        Offer storage o = offers[offerId];

        require(o.status == OfferStatus.Offered, "not offered");
        require(block.timestamp <= o.expiry,     "expired");

        address caller = _msgSender();
        address investor;

        if (o.delegatedTo != address(0)) {
            require(caller == o.delegatedTo, "delegated:auth");
            investor = o.investor;
        } else {
            require(caller == o.investor, "wrong investor");
            investor = caller;
        }

        // Verify investor signature over the same typed data.
        bytes32 structHash = keccak256(
            abi.encode(
                OFFER_TYPEHASH,
                o.issuer,
                o.investor,
                o.tokenAddress,
                o.partition,
                o.tokenId,
                o.amount,
                o.classId,
                o.nonceId,
                o.documentHash,
                keccak256(bytes(o.documentURI)),
                o.expiry,
                o.nonce
            )
        );
        require(
            _hashTypedDataV4(structHash).recover(investorSig) == o.investor,
            "bad sig"
        );

        o.status = OfferStatus.Accepted;
        _transfer(o.investor, o);
        isSettled[offerId] = true;

        emit OfferSettled(
            offerId, o.issuer, o.investor, o.tokenAddress, o.partition,
            o.tokenId, o.classId, o.nonceId, o.amount,
            o.documentHash, o.documentURI, o.expiry, o.nonce,
            o.issuerSig, investorSig
        );

        delete offers[offerId];
        emit OfferCleanedUp(offerId);
    }

    /**
     * @notice Reject an offered (non-expired) offer; only the designated investor can reject.
     *         Escrow is returned to the issuer and the offer is deleted.
     *
     * @param offerId  The id of the offer to reject.
     *
     * @dev
     * - Requirements:
     *   * `status == Offered`
     *   * `msg.sender == investor`
     * - Effects:
     *   * Status set to Rejected, escrow returned to issuer.
     *   * Offer storage entry deleted and cleanup event emitted.
     * - Emits: `OfferRejected(offerId)`, `OfferCleanedUp(offerId)`.
     *
     * @custom:reverts
     * - "Not offered" if `status != Offered`
     * - "Wrong investor" if caller is not the designated investor
     */
    function rejectOffer(bytes32 offerId) external whenNotPaused nonReentrant {
        Offer storage o = offers[offerId];
        address investor = _msgSender();
        require(o.status == OfferStatus.Offered, "Not offered");
        require(investor == o.investor,          "Wrong investor");

        o.status = OfferStatus.Rejected;
        _transfer(o.issuer, o);

        emit OfferRejected(offerId);
        delete offers[offerId];
        emit OfferCleanedUp(offerId);
    }

    /*────────────────────── Escrow / Transfer ────────────────────*/

    /**
     * @notice Internal escrow routine invoked by `offer(...)`.
     *
     * @param tokenAddress  Asset contract to escrow from `msg.sender`.
     * @param partition     ERC-1400 partition (ignored for others).
     * @param tokenId       ERC721/1155 id (0 for fungibles).
     * @param amount        ERC20/1400/1155/3475 quantity (1 for single ERC721).
     * @param classId       ERC-3475 class id (0 for others).
     * @param nonceId       ERC-3475 nonce id (0 for others).
     *
     * @dev
     * - If `tokenAddress == address(0)`, verifies escrowless params are zero and returns.
     * - Detection order: ERC1400 -> ERC3475 -> ERC721 -> ERC1155 -> (fallback) ERC20.
     * - Caller must have granted the contract sufficient allowance/approval/operator status.
     *
     * @custom:reverts
     * - "escrowless params" when escrowless but parameters indicate asset movement.
     * - Any revert bubbling from token contracts (e.g., insufficient approval, invalid ids).
     */
    function _escrow(
        address tokenAddress,
        bytes32 partition,
        uint256 tokenId,
        uint256 amount,
        uint256 classId,
        uint256 nonceId
    ) internal {
        if (tokenAddress == address(0)) {
            require(
                tokenId == 0 && amount == 0 && classId == 0 && nonceId == 0,
                "escrowless params"
            );
            return;
        }
        address candidate = tokenAddress;

        if (candidate.safeSupportsInterface(type(IERC1400).interfaceId)) {
            IERC1400(tokenAddress).transferByPartition(partition, address(this), amount, "");
        } else if (candidate.safeSupportsInterface(type(IERC3475).interfaceId)) {
            IERC3475(tokenAddress).operatorTransferFrom(
                _msgSender(),
                address(this),
                classId,
                nonceId,
                amount
            );
        } else if (candidate.safeSupportsInterface(type(IERC721).interfaceId)) {
            IERC721(tokenAddress).safeTransferFrom(_msgSender(), address(this), tokenId);
        } else if (candidate.safeSupportsInterface(type(IERC1155).interfaceId)) {
            IERC1155(tokenAddress).safeTransferFrom(_msgSender(), address(this), tokenId, amount, "");
        } else {
            IERC20(tokenAddress).safeTransferFrom(_msgSender(), address(this), amount);
        }
    }

    /**
     * @notice Internal settlement routine to deliver assets to `to`.
     *
     * @param to  Recipient address (issuer on cancel/reject; investor on accept).
     * @param o   Offer storage reference (must reflect the escrowed asset).
     *
     * @dev Mirrors `_escrow` detection order and uses the corresponding transfer operation.
     *      No-op for escrowless offers (`tokenAddress == address(0)`).
     */
    function _transfer(address to, Offer storage o) internal {
        if (o.tokenAddress == address(0)) {
            return;
        }
        address candidate = o.tokenAddress;

        if (candidate.safeSupportsInterface(type(IERC1400).interfaceId)) {
            IERC1400(o.tokenAddress).transferByPartition(o.partition, to, o.amount, "");
        } else if (candidate.safeSupportsInterface(type(IERC3475).interfaceId)) {
            IERC3475(o.tokenAddress).operatorTransferFrom(address(this), to, o.classId, o.nonceId, o.amount);
        } else if (candidate.safeSupportsInterface(type(IERC721).interfaceId)) {
            IERC721(o.tokenAddress).safeTransferFrom(address(this), to, o.tokenId);
        } else if (candidate.safeSupportsInterface(type(IERC1155).interfaceId)) {
            IERC1155(o.tokenAddress).safeTransferFrom(address(this), to, o.tokenId, o.amount, "");
        } else {
            IERC20(o.tokenAddress).safeTransfer(to, o.amount);
        }
    }

    /**
     * @notice Read-only fetch of a stored Offer.
     * @param id  offerId computed at creation.
     * @return Offer A memory copy of the stored offer.
     */
    function getOffer(bytes32 id) external view returns (Offer memory) {
        return offers[id];
    }

    /**
     * @notice Raise a dispute record (no fund movement).
     * @param offerId      (Optional) related offer id (use 0x0 if not applicable).
     * @param evidenceURI  Pointer to evidence (IPFS/HTTPS).
     *
     * @dev
     * - Anyone can raise; duplicates guarded by unique id hash (sender, timestamp, offerId, evidenceURI).
     * - Effects: stores Dispute with status=Raised and emits `DisputeRaised`.
     *
     * @custom:reverts
     * - "duplicate" if computed dispute id already exists.
     */
    function raiseDispute(bytes32 offerId, string calldata evidenceURI)
        external
        whenNotPaused
    {
        bytes32 id = keccak256(abi.encode(_msgSender(), block.timestamp, offerId, evidenceURI));
        require(_disputes[id].status == DisputeStatus.None, "duplicate");

        _disputes[id] = Dispute({
            claimant   : _msgSender(),
            offerId    : offerId,
            evidenceURI: evidenceURI,
            status     : DisputeStatus.Raised,
            createdAt  : uint64(block.timestamp)
        });

        emit DisputeRaised(id, offerId, _msgSender(), evidenceURI);
    }

    /**
     * @notice Update dispute status; only GUARDIAN_ROLE (e.g., ADR operator) can change status.
     * @param id         Dispute id computed at raise-time.
     * @param newStatus  Target status (must be one of: Acknowledged, Resolved, Rejected).
     *
     * @dev
     * - Requirements:
     *   * dispute must exist
     *   * `newStatus` must be > Raised
     *   * cannot set the same status repeatedly
     * - Emits: `DisputeStatusChanged(id, newStatus)`.
     *
     * @custom:reverts
     * - "unknown dispute" if not found
     * - "invalid" if `newStatus <= Raised`
     * - "same status" if no state change
     */
    function setDisputeStatus(bytes32 id, DisputeStatus newStatus)
        external
        onlyRole(GUARDIAN_ROLE)
    {
        Dispute storage d = _disputes[id];
        require(d.status != DisputeStatus.None, "unknown dispute");
        require(newStatus > DisputeStatus.Raised, "invalid");
        require(newStatus != d.status, "same status");

        d.status = newStatus;
        emit DisputeStatusChanged(id, newStatus);
    }

    /**
     * @notice Read-only fetch of a stored Dispute.
     * @param id  disputeId computed at raise-time.
     * @return Dispute  Memory copy of the dispute struct.
     */
    function getDispute(bytes32 id) external view returns (Dispute memory) {
        return _disputes[id];
    }

    /*────────────────── PAUSABLE (A6) ──────────────────*/

    /**
     * @notice Pause state-changing functions; only PAUSER_ROLE.
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause();   }

    /**
     * @notice Unpause state-changing functions; only PAUSER_ROLE.
     */
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /**
     * @notice ERC165 support; merges parents.
     * @param id  Interface id to probe.
     * @return bool Whether the interface is supported.
     */
    function supportsInterface(bytes4 id)
        public view override(AccessControlEnumerableUpgradeable, ERC1155Holder)
        returns (bool)
    {
        return super.supportsInterface(id);
    }

    /*────────────────────── UUPS auth ────────────────────────────*/

    /**
     * @notice UUPS upgrade authorization; only ADMIN_ROLE may upgrade.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /*────────────────────── Storage gap ──────────────────────────*/

    /**
     * @dev Reserved storage to allow future variable additions (per OZ guidelines).
     */
    uint256[48] private __gap;
}

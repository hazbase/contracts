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

import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* -------------------- Minimal external interfaces -------------------- */

interface IBondToken {
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
    function balanceOf(address, uint256, uint256) external view returns (uint256);
    function supportsInterface(bytes4) external view returns (bool);
}

enum OfferStatus { None, Offered, Accepted, Rejected, Cancelled }

struct Offer {
    address issuer;
    address investor;
    address tokenAddress;
    bytes32 partition;
    uint256 tokenId;
    uint256 classId;
    uint256 nonceId;
    uint256 amount;
    bytes32 documentHash;
    string documentURI;
    uint256 expiry;
    uint256 nonce;
    address delegatedTo;
    bytes issuerSig;
    OfferStatus status;
}

interface IAgreementManager {
    function getOffer(bytes32 id) external view returns (Offer memory);
    function acceptOffer(bytes32 offerId, bytes calldata investorSig) external;
}

interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

interface ISplitter {
    function routeERC20(IERC20 token, uint256 amount) external;
    function routeNative() external payable;
}

/**
 *  @title MarketManager
 *
 *  @notice
 *  - Purpose: Unified primary-sale market manager supporting:
 *      * On-chain fixed-price listings (“Asks”) with per-wallet caps, time windows, protocol fee, and optional royalty.
 *      * Off-chain EIP-712 vouchers (lazy listings) with partial fills tracked per voucher digest (salt-based).
 *      * Multi-asset escrow & settlement: ERC20, ERC721, ERC1155, and ERC-3475–like “BOND” (class/nonce).
 *      * Optional KYC whitelist and fee routing to an external Splitter (ERC20 & native).
 *      * Optional integration with AgreementManager offers (delegated “Ask” that settles via `acceptOffer`).
 *
 *  - Flows:
 *      * On-chain Ask:
 *          1) Seller calls `createAsk(...)`. If `agreement == 0`, assets are escrowed into this contract.
 *             If `agreement != 0`, an AgreementManager offer is referenced and validated; assets remain delegated.
 *          2) Buyer calls `fillAsk(...)` (or `fillAskWithPermit/withSig`) within time/cap constraints.
 *             For delegated asks, buyer must purchase the full lot; the contract calls `AgreementManager.acceptOffer`.
 *          3) Payment is split: protocol fee → Splitter, royalty → receiver, net → seller (ETH or ERC20).
 *      * Voucher:
 *          * Seller signs `Voucher` (EIP-712) off-chain; any buyer can `fillVoucher(...)` with the signature.
 *            Partial fills are tracked by digest up to `v.quantity`. Asset moves directly seller → buyer.
 *
 *  @dev SECURITY / AUDIT NOTES
 *  - Strict caps: `feeBps + royaltyBps ≤ 10_000`, ETH branch enforces `msg.value == gross`.
 *  - ERC20 branch supports EIP-2612 `permit` for gasless allowance set.
 *  - KYC is enforced on buyers if registry present.
 *  - Voucher replay: digest (typed-data) is tracked in `_voucherFilled` for partial fill limits.
 *  - Agreement integration: delegated asks require `qty == remaining` and metadata match with the offer.
 *  - Upgradeability: UUPS with `_authorizeUpgrade` gated by ADMIN_ROLE.
 *  - Meta-tx: ERC-2771 supported via overrides of `_msgSender/_msgData`.
 */

contract MarketManager is
    Initializable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    EIP712,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    using SafeERC20 for IERC20;
    using SafeERC20 for IERC20Metadata;
    using ECDSA   for bytes32;

    /*────────────────────── Fees / Treasury ─────────────────────*/

    /// @notice Protocol fee in basis points (10000 = 100%).
    uint16  public feeBps;

    /// @notice External fee router. Receives fees via `routeERC20/routeNative`.
    ISplitter public splitter;

    /*────────────────────────── KYC ────────────────────────────*/

    /// @notice Optional whitelist registry. If set, buyers must be whitelisted.
    IWhitelist public kyc;

    /// @notice Allowed ERC20 payment tokens. `address(0)` represents native ETH.
    mapping(address => bool) public allowedPaymentToken; // address(0)==ETH

    /// @dev EIP-712 domain cache (helpful across upgrades).
    uint256 private immutable INITIAL_CHAIN_ID;
    bytes32 private immutable INITIAL_DOMAIN_SEPARATOR;

    /*──────────────────────── Assets ───────────────────────────*/

    /// @dev Supported asset kinds.
    enum AssetKind { ERC20, ERC721, ERC1155, BOND }

    /**
     * @dev Asset descriptor
     * - ERC20:  `amount` = per-unit token amount transferred *per unit purchased*.
     * - ERC721: `id`     = tokenId (quantity must be 1 per unit).
     * - ERC1155:`id`     = tokenId, `qty` multiplied on transfer.
     * - BOND   : ERC3475-like; `id`=classId, `nonceId` used, `amount` = units per unit purchased.
     */
    struct Asset {
        AssetKind kind;
        address   token;
        uint256   id;
        uint256   nonceId; // BOND only
        uint256   amount;  // ticket size (per unit)
    }

    /**
     * @dev EIP-2612 permit data to set spending allowance for ERC20 payments.
     */
    struct PermitData {
        uint256  value;      // recommended: price*qty
        uint256  deadline;
        uint8    v; bytes32 r; bytes32 s;
    }

    /*──────────────────────── On-chain Ask ─────────────────────*/

    /**
     * @dev Fixed-price listing stored on-chain.
     * @param seller            Listing owner.
     * @param asset             Asset descriptor (see Asset).
     * @param price             Price per 1 unit (in `paymentToken` decimals or ETH).
     * @param paymentToken      Address(0)=ETH, else ERC20.
     * @param quantity          Remaining units available.
     * @param maxPerWallet      Per-wallet cap (0 = unlimited).
     * @param startTime         Start timestamp (if 0 set to now on create).
     * @param endTime           End timestamp (0 = open-ended).
     * @param royaltyReceiver   Receiver of royalty (optional if royaltyBps==0).
     * @param royaltyBps        Royalty bps (0..10000). Must satisfy `feeBps + royaltyBps ≤ 10000`.
     * @param agreement         Optional AgreementManager address (delegated settlement).
     * @param offerId           Offer id at AgreementManager (required if `agreement != 0`).
     */
    struct Ask {
        address seller;
        Asset   asset;
        uint256 price;
        address paymentToken;
        uint256 quantity;
        uint64  maxPerWallet;
        uint64  startTime;
        uint64  endTime;

        address royaltyReceiver;
        uint16  royaltyBps;

        address agreement;
        bytes32 offerId;
    }

    /// @dev Storage of all asks (by id).
    Ask[] private _asks;

    /// @dev Per-buyer counters: buyer => askId => cumulative purchased units.
    mapping(address => mapping(uint256 => uint256)) private _bought;

    /// @notice Accrued (failed-to-route) ERC20 fees.
    mapping(IERC20 => uint256) public pendingFee;

    /// @notice Accrued (failed-to-route) native fees.
    uint256 public pendingNative;

    /*──────────────────────── Vouchers (EIP-712) ─────────────────────────*/

    /// @dev EIP-712 typehash for Voucher (and embedded Asset).
    bytes32 private constant VOUCHER_TYPEHASH = keccak256(
        "Voucher(Asset asset,uint256 price,address paymentToken,uint256 quantity,uint64 maxPerWallet,uint64 startTime,uint64 endTime,address royaltyReceiver,uint16 royaltyBps,uint256 salt,address seller)Asset(uint8 kind,address token,uint256 id,uint256 nonceId,uint256 amount)"
    );

    /**
     * @dev Off-chain signed listing.
     * - `salt` uniquely identifies the voucher; its digest tracks partial fills up to `quantity`.
     */
    struct Voucher {
        Asset    asset;
        uint256  price;
        address  paymentToken;
        uint256  quantity;
        uint64   maxPerWallet;
        uint64   startTime;
        uint64   endTime;
        address  royaltyReceiver;
        uint16   royaltyBps;
        uint256  salt;
        address  seller;
    }

    /// @dev voucherDigest => filled units (supports partial fills).
    mapping(bytes32 => uint256) private _voucherFilled;

    /*────────────────────────── Events ─────────────────────────*/

    event AskCreated(uint256 indexed askId, address indexed seller, Asset asset, uint256 qty, uint256 price, address payToken);
    event AskCancelled(uint256 indexed askId);
    event AskFilled(uint256 indexed askId, address indexed buyer, uint256 qty, uint256 totalPaid, uint256 fee, uint256 royalty, uint256 net);
    event VoucherFilled(bytes32 indexed voucherHash, address indexed buyer, uint256 qty, uint256 totalPaid, uint256 fee, uint256 royalty, uint256 net);
    event FeePending(IERC20 indexed token, uint256 amount);
    event FeeFlushed(IERC20 indexed token, uint256 amount);

    /*──────────────────────── Initializer ─────────────────────*/

    /**
     * @notice Constructor disables initializers (UUPS pattern) and seeds EIP-712 domain cache.
     */
    constructor() EIP712("MarketManager", "1") {
        _disableInitializers();
        INITIAL_CHAIN_ID         = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _domainSeparatorV4();
    }

    /**
     * @notice Initialize the MarketManager (proxy).
     * @param admin       Admin address for RolesCommon (granted ADMIN/PAUSER/GUARDIAN etc.).
     * @param _splitter   Fee router (Splitter) address.
     * @param _bps        Protocol fee in bps (≤ 1000 recommended).
     * @param forwarders  Trusted ERC-2771 forwarders for meta-tx.
     *
     * @dev Calls initializers for ReentrancyGuard, Pausable, UUPS, ERC2771, and RolesCommon.
     */
    function initialize(
        address admin,
        address _splitter,
        uint16 _bps,
        address[] calldata forwarders
    ) external initializer {
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        splitter = ISplitter(_splitter);
        feeBps   = _bps;
    }

    /**
     * @notice Safe mul helper with overflow check.
     * @param a First multiplicand.
     * @param b Second multiplicand.
     * @return c Product `a * b` (reverts on overflow).
     */
    function _mul(uint256 a, uint256 b) internal pure returns (uint256 c) {
        if (a == 0 || b == 0) return 0;
        c = a * b;
        require(c / a == b, "mul overflow");
    }

    /*──────────────────────── Admin Setters ───────────────────*/

    /**
     * @notice Update protocol fee and fee router.
     * @param bps New fee in bps (must be ≤ 1000 in this implementation).
     * @param to  Splitter address to receive fees.
     *
     * @custom:reverts fee>10%        if `bps > 1000`
     * @custom:reverts fee receiver zero if `to == address(0)`
     */
    function setFee(uint16 bps, address to) external onlyRole(ADMIN_ROLE) {
        require(bps <= 1000, "fee>10%");
        require(to != address(0), "fee receiver zero");
        feeBps  = bps;
        splitter = ISplitter(to);
    }

    /**
     * @notice Allow or disallow a payment token.
     * @param token    ERC20 address (or address(0) to refer to ETH).
     * @param allowed  True to allow, false to disallow.
     */
    function setPaymentToken(address token, bool allowed) external onlyRole(ADMIN_ROLE) {
        allowedPaymentToken[token] = allowed;
    }

    /**
     * @notice Set the optional whitelist registry.
     * @param w Whitelist contract (or zero to disable KYC checks).
     */
    function setWhitelist(address w) external onlyRole(ADMIN_ROLE) { kyc = IWhitelist(w); }

    /* =======================================================================
                                    On-chain Ask
       =======================================================================*/

    /**
     * @notice Create a fixed-price listing.
     * @param asset            Asset descriptor.
     * @param price            Price per 1 unit.
     * @param paymentToken     Address(0)=ETH, else ERC20 (must be allowed if non-zero).
     * @param quantity         Units to list (must be > 0).
     * @param maxPerWallet     Per-wallet cap (0 = unlimited).
     * @param startTime        Start timestamp (0 ⇒ now).
     * @param endTime          End timestamp (0 ⇒ open-ended, else must be > now).
     * @param royaltyReceiver  Address to receive royalty (required if royaltyBps>0).
     * @param royaltyBps       Royalty in bps (feeBps + royaltyBps ≤ 10000).
     * @param agreement        Optional AgreementManager address for delegated ask.
     * @param offerId          Offer id (required if `agreement != 0`).
     * @return askId           Newly assigned ask id.
     *
     * @dev
     * - If `agreement == 0`: asset is escrowed into this contract immediately.
     * - If `agreement != 0`: verifies metadata match to the external `Offer`; asset remains delegated.
     * - Emits `AskCreated`.
     *
     * @custom:reverts zero param     if `quantity==0` or `price==0`
     * @custom:reverts bad end        if endTime != 0 and `endTime <= now`
     * @custom:reverts start too far  if startTime > now + 365 days
     * @custom:reverts royalty bad    if `royaltyBps>10000` or `feeBps+royaltyBps>10000`
     * @custom:reverts payToken !allowed if non-zero paymentToken not allowed
     * @custom:reverts ROYALTY_ZERO  if royaltyBps>0 but receiver==0
     * @custom:reverts offerId=0     if delegated ask without offer id
     * @custom:reverts mismatches    if delegated ask metadata does not equal `Offer`
     */
    function createAsk(
        Asset calldata asset,
        uint256 price,
        address paymentToken,
        uint256 quantity,
        uint64  maxPerWallet,
        uint64  startTime,
        uint64  endTime,
        address royaltyReceiver,
        uint16  royaltyBps,
        address agreement,
        bytes32 offerId
    ) external whenNotPaused returns (uint256 askId) {
        require(quantity > 0 && price > 0, "zero param");
        require(endTime == 0 || endTime > block.timestamp, "bad end");
        require(startTime <= block.timestamp + 365 days, "start too far");
        require(royaltyBps <= 10000 && feeBps + royaltyBps <= 10000, "royalty bad");
        require(paymentToken == address(0) || allowedPaymentToken[paymentToken], "payToken !allowed");
        require(royaltyBps == 0 || royaltyReceiver != address(0), "ROYALTY_ZERO");
        
        if (agreement == address(0)) {
            _escrowAsset(_msgSender(), address(this), asset, quantity);
        } else {
            require(offerId != bytes32(0), "offerId=0");
            Offer memory a = IAgreementManager(agreement).getOffer(offerId);
            require(quantity == a.amount, "qty != offer");
            require(asset.id == a.classId, "classId mismatch");
            require(asset.nonceId == a.nonceId, "nonceId mismatch");
            require(asset.token == a.tokenAddress, "token mismatch");
        }
        
        askId = _asks.length;
        _asks.push(
            Ask({
                seller: _msgSender(),
                asset:  asset,
                price:  price,
                paymentToken: paymentToken,
                quantity: quantity,
                maxPerWallet: maxPerWallet,
                startTime: startTime == 0 ? uint64(block.timestamp) : startTime,
                endTime:   endTime,
                royaltyReceiver: royaltyReceiver,
                royaltyBps: royaltyBps,
                agreement: agreement,
                offerId: offerId
            })
        );
        emit AskCreated(askId, _msgSender(), asset, quantity, price, paymentToken);
    }

    /**
     * @notice Cancel an active on-chain ask and return escrowed assets to seller.
     * @param askId Ask id to cancel.
     *
     * @dev Disallowed for delegated asks (use AgreementManager’s cancel).
     * @custom:reverts sold-out if `quantity == 0`
     * @custom:reverts not seller if caller is not the original seller
     * @custom:reverts delegated ask: use AM cancel if `agreement != 0`
     */
    function cancelAsk(uint256 askId) external nonReentrant {
        Ask storage a = _asks[askId];
        require(a.quantity > 0, "sold-out");
        require(a.seller == _msgSender(), "not seller");
        require(a.agreement == address(0), "delegated ask: use AM cancel");

        uint256 qty = a.quantity;
        a.quantity = 0;

        _transferAsset(address(this), a.seller, a.asset, qty);
        emit AskCancelled(askId);
    }

    /**
     * @notice Buy `qty` units from an on-chain ask (ETH payment requires `msg.value`).
     * @param askId Ask id.
     * @param qty   Units to buy.
     *
     * @dev For delegated asks, must buy full remaining lot and pass `investorSig` via `fillAskWithSig`.
     */
    function fillAsk(uint256 askId, uint256 qty)
        external payable nonReentrant whenNotPaused {
            _fillAskInternal(askId, qty, "", PermitData(0,0,0,bytes32(0),bytes32(0)));
    }

    /**
     * @notice Buy with EIP-2612 `permit` and AgreementManager investor signature.
     * @param askId       Ask id.
     * @param qty         Units to buy.
     * @param permit      ERC20 permit (optional; set to zero fields to skip).
     * @param investorSig Investor signature (EIP-712) required if ask is delegated (`agreement != 0`).
     */
    function fillAskWithPermit(
        uint256 askId,
        uint256 qty,
        PermitData calldata permit,
        bytes memory investorSig
    ) external payable nonReentrant whenNotPaused
    { _fillAskInternal(askId, qty, investorSig, permit); }

    /**
     * @notice Buy and pass AgreementManager investor signature (no permit).
     * @param askId       Ask id.
     * @param qty         Units to buy.
     * @param investorSig Investor signature (EIP-712) required for delegated asks.
     */
    function fillAskWithSig(
        uint256 askId,
        uint256 qty,
        bytes   memory investorSig
    ) external payable nonReentrant whenNotPaused
    { _fillAskInternal(askId, qty, investorSig, PermitData(0,0,0,bytes32(0),bytes32(0))); }

    /**
     * @notice Internal settlement for on-chain ask.
     * @param askId       Ask id.
     * @param qty         Units to buy.
     * @param investorSig Investor signature for delegated asks (ignored otherwise).
     * @param permit      ERC20 permit for payment token (optional).
     *
     * @dev
     * - Checks time window, per-wallet cap, and KYC.
     * - Updates remaining quantity and per-wallet accounting.
     * - Delegated asks require full-lot purchase and call `AgreementManager.acceptOffer`.
     * - Non-delegated asks transfer asset out of escrow.
     * - Charges fee/royalty & pays seller via `_collectPayment`.
     * - Emits `AskFilled`.
     *
     * @custom:reverts bad qty     if `qty==0` or `qty>remaining`
     * @custom:reverts not started if now < startTime
     * @custom:reverts ended       if endTime != 0 and now > endTime
     * @custom:reverts cap exceeded if per-wallet limit exceeded
     * @custom:reverts must buy full lot if delegated and `qty != remaining`
     */
    function _fillAskInternal(
        uint256 askId,
        uint256 qty,
        bytes   memory investorSig,
        PermitData memory permit
    ) internal {
        Ask storage a = _asks[askId];

        /* -------- Checks -------- */
        require(qty > 0 && qty <= a.quantity, "bad qty");
        require(block.timestamp >= a.startTime,                "not started");
        require(a.endTime == 0 || block.timestamp <= a.endTime,"ended");
        _kycCheck(_msgSender());

        /* per-wallet cap */
        uint256 newSpent;
        if (a.maxPerWallet != 0) {
            newSpent = _bought[_msgSender()][askId] + qty;
            require(newSpent <= a.maxPerWallet, "cap exceeded");
        }

        uint256 prevQty = a.quantity;
        a.quantity -= qty;
        if (a.maxPerWallet != 0) {
            _bought[_msgSender()][askId] = newSpent;
        }

        if (a.agreement != address(0)) {
            require(qty == prevQty, "must buy full lot");
            IAgreementManager(a.agreement).acceptOffer(a.offerId, investorSig);
        }

        if (a.agreement == address(0)) {
            _transferAsset(address(this), _msgSender(), a.asset, qty);
        }

        (uint256 gross,uint256 fee,uint256 royalty,uint256 net) = _collectPayment(
            a.paymentToken,
            a.price,
            qty,
            a.seller,
            a.royaltyReceiver,
            a.royaltyBps,
            permit
        );

        emit AskFilled(askId, _msgSender(), qty, gross, fee, royalty, net);
    }

    /* =======================================================================
                                Vouchers (EIP-712)
       =======================================================================*/

    /**
     * @notice Redeem a signed voucher to buy `qty` units (no permit).
     * @param v     Voucher struct (asset, price, window, royalty, salt, seller).
     * @param qty   Units to buy (must not exceed remaining voucher quantity).
     * @param sig   Seller signature over the voucher (EIP-712).
     *
     * @dev Transfers asset from `v.seller` directly to buyer and performs payment split.
     */
    function fillVoucher(
        Voucher   calldata v,
        uint256           qty,
        bytes     calldata sig
    ) external payable nonReentrant whenNotPaused
    { _fillVoucherInternal(v, qty, sig, PermitData(0,0,0,bytes32(0),bytes32(0))); }

    /**
     * @notice Redeem a signed voucher to buy `qty` units (with ERC20 permit).
     * @param v       Voucher struct.
     * @param qty     Units to buy.
     * @param sig     Seller signature over the voucher.
     * @param permit  ERC20 permit for payment token (optional).
     */
    function fillVoucherWithPermit(
        Voucher   calldata v,
        uint256           qty,
        bytes     calldata sig,
        PermitData calldata permit
    ) external payable nonReentrant whenNotPaused
    { _fillVoucherInternal(v, qty, sig, permit); }
    
    /**
     * @notice Internal voucher settlement.
     * @param v       Voucher struct.
     * @param qty     Units to buy.
     * @param sig     Seller signature.
     * @param permit  ERC20 permit (optional).
     *
     * @dev
     * - Verifies time window, fee+royalty sum, payment token allowlist.
     * - Recovers signer and enforces `signer == v.seller`.
     * - Enforces per-voucher partial fill limit and per-wallet cap.
     * - Enforces buyer KYC if registry set.
     * - Transfers asset seller → buyer and performs payment split.
     * - Emits `VoucherFilled`.
     *
     * @custom:reverts qty bad         if qty==0 or exceeds remaining voucher amount
     * @custom:reverts too early       if now < v.startTime
     * @custom:reverts voucher ended   if now > v.endTime (when set)
     * @custom:reverts bps sum         if feeBps + royaltyBps > 10000
     * @custom:reverts price 0         if v.price == 0
     * @custom:reverts payToken !allowed if non-zero paymentToken not allowed
     * @custom:reverts sig bad         if recovered signer != v.seller
     * @custom:reverts exhausted       if (filled + qty) > v.quantity
     * @custom:reverts cap exceeded    if per-wallet limit exceeded
     */
    function _fillVoucherInternal(
        Voucher   calldata v,
        uint256           qty,
        bytes     calldata sig,
        PermitData memory permit
    ) internal {
        /* -------- Checks -------- */
        require(qty > 0 && qty <= v.quantity,                  "qty bad");
        require(block.timestamp >= v.startTime,                "too early");
        require(v.endTime == 0 || block.timestamp <= v.endTime,"voucher ended");
        require(v.royaltyBps + feeBps <= 10_000,               "bps sum");
        require(v.price > 0,                                   "price 0");
        require(v.paymentToken == address(0) || allowedPaymentToken[v.paymentToken],
                "payToken !allowed");

        bytes32 digest = _hashVoucher(v);
        require(digest.recover(sig) == v.seller,               "sig bad");

        uint256 filled = _voucherFilled[digest];
        require(filled + qty <= v.quantity,                    "exhausted");

        uint256 newSpent;
        if (v.maxPerWallet != 0) {
            newSpent = _bought[_msgSender()][uint256(digest)] + qty;
            require(newSpent <= v.maxPerWallet, "cap exceeded");
        }

        _voucherFilled[digest] = filled + qty;
        if (v.maxPerWallet != 0) {
            _bought[_msgSender()][uint256(digest)] = newSpent;
        }

        _kycCheck(_msgSender());

        /* -------- Interactions -------- */
        _escrowAsset(v.seller, _msgSender(), v.asset, qty);
        (uint256 gross,uint256 fee,uint256 royalty,uint256 net) = _collectPayment(
            v.paymentToken,
            v.price,
            qty,
            v.seller,
            v.royaltyReceiver,
            v.royaltyBps,
            permit
        );

        emit VoucherFilled(digest, _msgSender(), qty, gross, fee, royalty, net);
    }

    /*──────────────────────── Internal helpers ─────────────────────*/

    /**
     * @notice Compute the EIP-712 digest for a Voucher (with embedded Asset).
     * @param v Voucher struct.
     * @return bytes32 EIP-712 digest for signature recovery.
     */
    function _hashVoucher(Voucher calldata v) internal view returns (bytes32) {
        bytes32 assetHash = keccak256(
            abi.encode(
                keccak256("Asset(uint8 kind,address token,uint256 id,uint256 nonceId,uint256 amount)"),
                v.asset.kind,
                v.asset.token,
                v.asset.id,
                v.asset.nonceId,
                v.asset.amount
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                VOUCHER_TYPEHASH,
                assetHash,
                v.price,
                v.paymentToken,
                v.quantity,
                v.maxPerWallet,
                v.startTime,
                v.endTime,
                v.royaltyReceiver,
                v.royaltyBps,
                v.salt,
                v.seller
            )
        );
        return _hashTypedDataV4(structHash);
    }

    /**
     * @notice Enforce whitelist rule on `user` when KYC registry is set.
     * @param user Address to check.
     * @custom:reverts KYCfail if registry exists and `user` is not whitelisted.
     */
    function _kycCheck(address user) internal view {
        if (address(kyc) != address(0)) {
            require(kyc.isWhitelisted(user), "KYCfail");
        }
    }

    /**
     * @notice Route ERC20 fees to Splitter; accrue to `pendingFee` on failure.
     * @param tok ERC20 metadata token.
     * @param amt Amount to route (0 is a no-op).
     */
    function _pushFee(IERC20Metadata tok, uint256 amt) internal {
        if (amt == 0) return;

        if (address(splitter).code.length == 0) {
            tok.safeTransfer(address(splitter), amt);
        } else {
            if (tok.allowance(address(this), address(splitter)) < amt) {
                tok.safeIncreaseAllowance(address(splitter), amt);
            }
            try splitter.routeERC20(tok, amt) {
            } catch {
                pendingFee[tok] += amt;
                emit FeePending(tok, amt);
            }
        }
    }

    /**
     * @notice Flush (part of) accrued ERC20 fees to Splitter.
     * @param tok        ERC20 token to flush.
     * @param maxAmount  Max amount to flush (0 = all).
     *
     * @custom:reverts no pending if nothing to flush.
     */
    function flushFees(IERC20Metadata tok, uint256 maxAmount)
        external nonReentrant whenNotPaused
    {
        uint256 amt = pendingFee[tok];
        if (maxAmount > 0 && maxAmount < amt) amt = maxAmount;
        require(amt > 0, "no pending");

        pendingFee[tok] -= amt;
        _pushFee(tok, amt);
        
        emit FeeFlushed(tok, amt);
    }

    /**
     * @notice Route native fee to Splitter; accrue to `pendingNative` on failure.
     * @param amount Amount in wei.
     */
    function _pushNative(uint256 amount) internal {
        (bool ok, ) = address(splitter).call{value: amount}(
            abi.encodeWithSignature("routeNative()")
        );
        if (!ok) {
            pendingNative += amount;
        }
    }

    /**
     * @notice Flush (part of) accrued native fees to Splitter.
     * @param maxAmt  Max amount to flush (0 = all).
     */
    function flushNative(uint256 maxAmt) external nonReentrant whenNotPaused {
        uint256 amt = pendingNative;
        if (maxAmt != 0 && maxAmt < amt) amt = maxAmt;
        pendingNative -= amt;
        _pushNative(amt); // routeNative + try/catch
    }

    /**
     * @notice Collect payment from buyer and distribute fee/royalty/net.
     * @param payToken     Address(0)=ETH, else ERC20 token.
     * @param pricePerUnit Price per unit.
     * @param qty          Units being purchased.
     * @param seller       Seller address to receive `net`.
     * @param royaltyRecv  Royalty receiver address (if royaltyBps > 0).
     * @param royaltyBps   Royalty bps (0..10000).
     * @param permit       Optional EIP-2612 permit to set allowance for ERC20 payments.
     * @return gross       Total price (= pricePerUnit * qty).
     * @return fee         Protocol fee portion.
     * @return royalty     Royalty portion.
     * @return net         Seller net (gross - fee - royalty).
     *
     * @dev
     * - ETH: `msg.value` must equal `gross`; fee is routed, royalty sent, and net sent to seller.
     * - ERC20: optionally calls `permit`, then pulls fee/royalty/net using `safeTransferFrom`.
     * - ERC20 fees are routed to Splitter via `_pushFee`.
     *
     * @custom:reverts ETH bad      if `msg.value != gross` for ETH payments
     */
    function _collectPayment(
        address payToken,
        uint256 pricePerUnit,
        uint256 qty,
        address seller,
        address royaltyRecv,
        uint16  royaltyBps,
        PermitData memory permit
    )
        internal
        returns (uint256 gross,uint256 fee,uint256 royalty,uint256 net)
    {
        gross   = _mul(pricePerUnit, qty);
        fee     = _mul(gross, feeBps)     / 10_000;
        royalty = _mul(gross, royaltyBps) / 10_000;
        net     = gross - fee - royalty;

        if (payToken == address(0)) {
            /* ---- ETH ---- */
            require(msg.value == gross, "ETH bad");
            if (fee != 0) _pushNative(fee);
            if (royalty != 0) _safeSendETH(royaltyRecv, royalty);
            _safeSendETH(seller, net);
        } else {
            /* ---- ERC-20 ---- */
            IERC20 token = IERC20(payToken);

            if (permit.value != 0) {
                IERC20Permit(payToken).permit(
                    _msgSender(),
                    address(this),
                    permit.value,
                    permit.deadline,
                    permit.v, permit.r, permit.s
                );
            }

            if (fee != 0) {
                token.safeTransferFrom(_msgSender(), address(this), fee);
                _pushFee(IERC20Metadata(payToken), fee);
            }
            if (royalty != 0) token.safeTransferFrom(_msgSender(), royaltyRecv, royalty);
            token.safeTransferFrom(_msgSender(), seller, net);
        }
    }

    /**
     * @notice Safe ETH send helper (bubbles bool revert into require).
     * @param to     Recipient.
     * @param amount Amount in wei.
     * @custom:reverts ETH send fail on failure.
     */
    function _safeSendETH(address to, uint256 amount) private {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "ETH send fail");
    }

    /*────────────── Escrow / Transfer helpers (internal) ─────────────*/

    /**
     * @notice Escrow `qty` units of `asset` from `from` to `to`.
     * @param from  Source address.
     * @param to    Destination address.
     * @param asset Asset descriptor.
     * @param qty   Units to escrow.
     */
    function _escrowAsset(
        address from,
        address to,
        Asset memory asset,
        uint256 qty
    ) internal {
        if (asset.kind == AssetKind.ERC721) {
            IERC721(asset.token).transferFrom(from, to, asset.id);
        } else if (asset.kind == AssetKind.ERC1155) {
            IERC1155(asset.token).safeTransferFrom(from, to, asset.id, qty, "");
        } else if (asset.kind == AssetKind.BOND) {
            IBondToken(asset.token).operatorTransferFrom(from, to, asset.id, asset.nonceId, qty);
        } else {
            IERC20(asset.token).safeTransferFrom(from, to, _mul(asset.amount, qty));
        }
    }

    /**
     * @notice Transfer `qty` units of `asset` from `from` to `to`.
     * @param from  Source address.
     * @param to    Destination address.
     * @param asset Asset descriptor.
     * @param qty   Units to transfer.
     */
    function _transferAsset(
        address from,
        address to,
        Asset memory asset,
        uint256 qty
    ) internal {
        if (asset.kind == AssetKind.ERC721) {
            IERC721(asset.token).safeTransferFrom(from, to, asset.id);
        } else if (asset.kind == AssetKind.ERC1155) {
            IERC1155(asset.token).safeTransferFrom(from, to, asset.id, qty, "");
        } else if (asset.kind == AssetKind.BOND) {
            IBondToken(asset.token).operatorTransferFrom(from, to, asset.id, asset.nonceId, qty);
        } else {
            IERC20(asset.token).safeTransferFrom(from, to, _mul(asset.amount, qty));
        }
    }

    /*──────────────────────────── Views ───────────────────────────*/

    /**
     * @notice Number of asks created.
     * @return uint256 length of `_asks`.
     */
    function asksLength() external view returns (uint256) { return _asks.length; }

    /**
     * @notice Read an ask by id.
     * @param id Ask id.
     * @return Ask Full ask struct.
     */
    function ask(uint256 id) external view returns (Ask memory) { return _asks[id]; }

    /**
     * @notice How many units of a voucher digest have been filled.
     * @param h Voucher digest returned by `_hashVoucher`.
     * @return uint256 Filled units.
     */
    function voucherFilled(bytes32 h) external view returns (uint256) { return _voucherFilled[h]; }

    /*────────────────────────── Pause ───────────────────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause(); }

    /**
     * @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
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
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /* ------------ ETH receive ------------ */

    /**
     * @notice Receive fallback to accept ETH (used for potential direct sends).
     * @dev Not used for swap logic; ETH payments are handled in `_collectPayment`.
     */
    receive() external payable {}

    /// @dev Storage gap for future variable additions.
    uint256[45] private __gap;
}

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

import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ─────────────  Debt-token minimal interface (ERC-3475 class) ───────────── */
/**
 * @dev Minimal snapshot-capable interface required by this manager.
 * - `snapshot()` returns a monotonically increasing snapshot id.
 * - `balanceOfAt` & `totalSupplyAt` query snapshot states.
 * - `burn` is used when principal is paid back against surrendered units.
 */
interface IERC3475Snapshot {
    function snapshot() external returns (uint256 id);
    function balanceOf(address owner,uint256 classId,uint256 nonceId) external view returns(uint256);
    function balanceOfAt(address owner,uint256 classId,uint256 nonceId,uint256 snapId) external view returns(uint256);
    function totalSupplyAt(uint256 classId,uint256 nonceId,uint256 snapId) external view returns(uint256);
    function burn(address from,uint256 classId,uint256 nonceId,uint256 amount) external;
    function totalSupply(uint256 classId,uint256 nonceId) external view returns(uint256);
}

/**
 *  @title DebtManager
 *
 *  @notice
 *  - Purpose: Lifecycle manager for ERC-3475–style bond tranches (class/nonce),
 *             covering coupon scheduling & payments (snapshot-based), call/put
 *             mechanics, default detection, principal funding/redemption, and
 *             tranche closeout with fee-less internal accounting.
 *  - Token model:
 *      * Debt token implements a minimal ERC-3475 snapshot interface (`IERC3475Snapshot`).
 *      * Coupon claims use `balanceOfAt(holder, classId, nonceId, snapshotId)` taken at payment time.
 *  - Flow highlights:
 *      * `createTranche` registers a unique (token,class,nonce) as PENDING.
 *      * `addCouponSchedule` appends coupon epochs; first append moves to ACTIVE.
 *      * `payCoupon` (issuer) takes a snapshot and provisions coupon funds.
 *      * Investors `claimCoupon` pro-rata vs snapshot.
 *      * Call/Put: issuer can notify call; investors can give put notice and exercise after notice period.
 *      * Default: if a due coupon remains unpaid after grace, status → DEFAULTED.
 *      * Maturity: investors redeem principal; issuer can close tranche and sweep residuals.
 *  - Security / Audit notes:
 *      * Principal protection: functions that pay out principal enforce `principalCovered` and a
 *        `noSameBlockFund` delay (≥5 blocks after last funding) to mitigate near-block MEV/griefing.
 *      * Snapshot math: `perUnit = totalPaid / supply` (integer division). Remainders remain unallocated.
 *        `claimed + amt <= totalPaid` enforces conservation.
 *      * Access control via RolesCommon: ADMIN_ROLE, MINTER_ROLE, PAUSER_ROLE; Meta-tx via ERC-2771.
 *      * Upgradeability: UUPS (`_authorizeUpgrade` gated by ADMIN_ROLE); storage gap reserved.
 */
 
contract DebtManager is
    Initializable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    using SafeERC20 for IERC20;

    /* ───────────── Library constants ───────────── */

    /// @notice Grace period added after coupon due date before default can be flagged.
    uint64  public constant COUPON_GRACE = 7 days;     // default grace period
    /// @notice Basis-points denominator (100% = 10_000).
    uint16  internal constant BPS_DENOM  = 10_000;     // Basis-points denominator
    /// @notice Grace period after maturity before issuer may sweep unclaimed coupon residuals.
    uint64  public constant SWEEP_GRACE  = 180 days;

    /* ───────────── Enum ───────────── */

    /**
     * @dev Tranche lifecycle:
     * PENDING -> ACTIVE -> (CALLED | PUT_NOTICE | DEFAULTED) -> MATURED
     * Note: PUT_NOTICE is also represented per-holder via `putNotice` mapping.
     */
    enum TrancheStatus { PENDING, ACTIVE, CALLED, PUT_NOTICE, DEFAULTED, MATURED }

    /* ───────────── Structs ───────────── */

    /**
     * @dev Coupon epoch metadata.
     * - `snapshotId`: taken at payment time to freeze entitlements.
     * - `perUnit`:   amount per 1 debt unit (integer division).
     */
    struct CouponSchedule {
        uint64  payDate;      // coupon due date (unix)
        uint256 rateBps;      // coupon rate in 1/100 %
        bool    paid;         // coupon paid flag
        uint256 totalPaid;    // ERC20 deposited by issuer
        uint256 claimed;      // running sum of claimed amount
        uint256 snapshotId;   // snapshot used for pro-rata
        uint256 perUnit;      // payout per debt unit at snapshot
    }

    /**
     * @dev Tranche state for a (token,class,nonce).
     * - `requiredPrincipal` grows/shrinks with supply and represents total principal yet to be funded.
     * - `principalPool` is the funded principal balance held by this contract.
     */
    struct Tranche {
        uint256 cachedSupply;
        uint256 requiredPrincipal;
        uint256  principalPool; 
        
        IERC3475Snapshot token;
        uint256  classId;
        uint256  nonceId;
        IERC20   principalToken;
        uint256  principalPerUnit;
        IERC20   couponToken;
        uint64   maturity;
        uint32   nextUnpaid;

        TrancheStatus status;
        CouponSchedule[] coupons;

        uint64  callPriceBps;
        uint64  putPriceBps;
        uint64  callNoticePeriod;
        uint64  putNoticePeriod;
        uint64  callNoticeTime;
        uint256 outstandingCoupon; // unpaid (yet-to-be claimed) coupon total
        mapping(address=>uint64) putNotice;                       // holder -> ts
        mapping(uint32=>mapping(address=>bool)) claimed;          // epoch -> holder -> claimed?
    }

    /* ───────────── Storage ───────────── */

    /// @dev Tranche registry; index is used in external API.
    Tranche[] private _tranches;

    /// @dev Active uniqueness control: (token,class,nonce) → active?
    mapping(bytes32 => bool) private _activeRegistry;

    /// @dev Last funding block per tranche; used by `noSameBlockFund` to delay payouts.
    mapping(uint256 => uint64) private _lastFundBlock;

    /* ───────────── Events ───────────── */

    event TrancheCreated(uint256 indexed idx, uint64 maturity);
    event CouponScheduleAdded(uint256 indexed idx, uint32 epoch, uint64 payDate, uint256 rateBps);
    event CouponPaid(uint256 indexed idx, uint32 epoch, uint256 totalAmount);
    event CouponClaimed(uint256 indexed idx, uint32 epoch, address indexed holder, uint256 amount);
    event CallNotified(uint256 indexed idx);
    event Called(uint256 indexed idx, address indexed holder, uint256 amount, uint256 pay);
    event PutNotified(uint256 indexed idx, address indexed holder);
    event PutExecuted(uint256 indexed idx, address indexed holder, uint256 amount);
    event Defaulted(uint256 indexed idx, uint32 missedEpoch);
    event PrincipalRedeemed(uint256 indexed idx, address indexed holder, uint256 amount);
    event TrancheClosed(uint256 indexed idx, address sweepTo);
    event PrincipalFunded(uint256 indexed idx, uint256 amount);
    event SupplyAdjusted(uint256 indexed idx, int256 dUnits, int256 dPrincipal);

    /* ───────────── Modifiers ───────────── */

    /**
     * @dev Require tranche status == ACTIVE.
     * @param idx Tranche index.
     */
    modifier onlyActive(uint256 idx) {
        require(_tranches[idx].status == TrancheStatus.ACTIVE, "not ACTIVE");
        _;
    }

    /**
     * @dev Require tranche status in {PENDING, ACTIVE}.
     * @param idx Tranche index.
     */
    modifier trancheOpen(uint256 idx){
        TrancheStatus s=_tranches[idx].status;
        require(s==TrancheStatus.PENDING||s==TrancheStatus.ACTIVE,"closed");
        _;
    }

    /**
     * @dev Require principalPool >= requiredPrincipal for tranche.
     * @param idx Tranche index.
     */
    modifier principalCovered(uint256 idx) {
        Tranche storage t = _tranches[idx];
        require(t.principalPool >= t.requiredPrincipal, "PRINCIPAL_NOT_FUNDED");
        _;
    }

    /**
     * @dev Require `amount > 0`.
     */
    modifier nonZero(uint256 amount) {
        require(amount > 0, "zero amount");
        _;
    }

    /**
     * @dev Enforce that at least one funding exists, and ≥5 blocks have passed since last funding.
     *      Reduces fund-and-immediately-withdraw risk.
     * @param idx Tranche index.
     */
    modifier noSameBlockFund(uint256 idx) {
        require(_lastFundBlock[idx] != 0, "NOT_FUNDED_YET");
        require(block.number > _lastFundBlock[idx] + 5, "WAIT_FEW_BLOCKS");
        _;
    }

    /* ───────────── Initializer / UUPS ───────────── */

    /**
     * @notice Disable initializers for implementation contract.
     */
    constructor() { _disableInitializers(); }

    /**
     * @notice Initialize the manager (proxy).
     * @param admin       Admin address (granted ADMIN/MINTER/PAUSER via RolesCommon).
     * @param forwarders  Trusted ERC-2771 forwarders.
     *
     * @dev Grants MINTER_ROLE to `admin`. No events emitted.
     */
    function initialize(
        address admin,
        address[] calldata forwarders
    ) external initializer {
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        _grantRole(MINTER_ROLE, admin);
    }

    /* ───────────── Admin: tranche creation ───────────── */

    /**
     * @notice Create a new tranche for (token,class,nonce) and register uniqueness.
     * @param token             ERC-3475 snapshot token.
     * @param classId           Class id.
     * @param nonceId           Nonce id.
     * @param principalToken    ERC20 used for principal payments.
     * @param principalPerUnit  Principal value per debt unit.
     * @param couponToken       ERC20 used for coupon payments.
     * @param maturity          UNIX timestamp of maturity.
     * @param callPriceBps      Call payout as bps of principal (≤ 10_000).
     * @param putPriceBps       Put payout as bps of principal (≤ 10_000).
     * @param callNoticeSec     Notice period (seconds) before call can be executed.
     * @param putNoticeSec      Notice period (seconds) after holder’s put notice.
     * @return idx              Tranche index.
     *
     * @dev
     * - Computes `requiredPrincipal = principalPerUnit * totalSupply`.
     * - Registers uniqueness guard in `_activeRegistry`.
     * - Sets status to PENDING; becomes ACTIVE when first coupon is added.
     *
     * @custom:reverts maturity past    if maturity ≤ now
     * @custom:reverts duplicate        if (token,class,nonce) already active
     * @custom:reverts bps>100%         if call/put bps > 10_000
     * @custom:reverts overflow         if multiplication overflows uint256
     */
    function createTranche(
        IERC3475Snapshot token,
        uint256 classId,
        uint256 nonceId,
        IERC20 principalToken,
        uint256 principalPerUnit,
        IERC20 couponToken,
        uint64 maturity,
        uint64 callPriceBps,
        uint64 putPriceBps,
        uint64 callNoticeSec,
        uint64 putNoticeSec
    ) external onlyRole(MINTER_ROLE) returns(uint256 idx){
        require(maturity>block.timestamp,"maturity past");
        bytes32 key=keccak256(abi.encode(bytes1(0x01),token,bytes1(0x02),classId,bytes1(0x03),nonceId));
        require(!_activeRegistry[key],"duplicate");
        require(callPriceBps<=BPS_DENOM&&putPriceBps<=BPS_DENOM,"bps>100%");

        idx=_tranches.length;

        Tranche storage t=_tranches.push();

        t.principalPool = 0;

        uint256 totalSupply = token.totalSupply(classId, nonceId);
        require(totalSupply <= type(uint256).max / principalPerUnit, "overflow");
        t.requiredPrincipal = principalPerUnit * totalSupply;

        t.token=token; t.classId=classId; t.nonceId=nonceId;
        t.principalToken=principalToken; t.principalPerUnit=principalPerUnit;
        t.couponToken=couponToken; t.maturity=maturity;
        t.status=TrancheStatus.PENDING;
        t.callPriceBps=callPriceBps; t.putPriceBps=putPriceBps;
        t.callNoticePeriod=callNoticeSec; t.putNoticePeriod=putNoticeSec;
        t.cachedSupply = totalSupply;

        _activeRegistry[key]=true;
        emit TrancheCreated(idx,maturity);
    }

    /* ───────────── Admin: add coupon schedule ───────────── */

    /**
     * @notice Append a coupon epoch (must be strictly increasing and before maturity).
     * @param idx      Tranche index.
     * @param payDate  Coupon due date (unix).
     * @param rateBps  Coupon rate in bps (informational).
     *
     * @dev First append moves status PENDING → ACTIVE and initializes `nextUnpaid`.
     * @custom:reverts after maturity if payDate ≥ maturity
     * @custom:reverts outoforder    if not strictly increasing by `payDate`
     */
    function addCouponSchedule(
        uint256 idx,
        uint64  payDate,
        uint256 rateBps
    ) external onlyRole(MINTER_ROLE) trancheOpen(idx) {
        Tranche storage t=_tranches[idx];
        require(payDate<t.maturity,"after maturity");
        if(t.coupons.length>0) require(payDate>t.coupons[t.coupons.length-1].payDate, "outoforder");
        t.coupons.push(CouponSchedule(payDate,rateBps,false,0,0,0,0));
        if(t.status==TrancheStatus.PENDING){t.status=TrancheStatus.ACTIVE; t.nextUnpaid=0;}
        emit CouponScheduleAdded(idx,uint32(t.coupons.length-1),payDate,rateBps);
    }

    /* ───────────── Admin: pay coupon & set snapshot ───────────── */

    /**
     * @notice Provision coupon funds and take a snapshot for the given epoch.
     * @param idx          Tranche index.
     * @param epoch        Coupon epoch index.
     * @param totalAmount  Total ERC20 amount to distribute for this epoch.
     *
     * @dev Transfers `totalAmount` from caller; sets `snapshotId` and `perUnit`.
     * @custom:reverts zero     if totalAmount == 0
     * @custom:reverts bad status if tranche not ACTIVE
     * @custom:reverts epoch!   if epoch is out of range
     * @custom:reverts paid     if epoch already paid
     * @custom:reverts early    if called before `payDate`
     * @custom:reverts redeemed if total supply at snapshot is 0
     */
    function payCoupon(
        uint256 idx,
        uint32  epoch,
        uint256 totalAmount
    ) external onlyRole(MINTER_ROLE) nonReentrant whenNotPaused {
        _payCouponInternal(idx, epoch, totalAmount);
    }

    /**
     * @notice Pay coupon with EIP-2612 permit on the coupon token.
     * @param idx          Tranche index.
     * @param epoch        Coupon epoch index.
     * @param totalAmount  Total amount to transfer from issuer.
     * @param deadline     Permit deadline.
     * @param v            ECDSA v.
     * @param r            ECDSA r.
     * @param s            ECDSA s.
     *
     * @dev Calls `permit` then `_payCouponInternal`.
     */
    function payCouponWithPermit(
        uint256 idx,
        uint32  epoch,
        uint256 totalAmount,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external onlyRole(MINTER_ROLE) nonReentrant whenNotPaused {
        Tranche storage t = _tranches[idx];
        IERC20Permit(address(t.couponToken)).permit(_msgSender(), address(this), totalAmount, deadline, v, r, s);
        _payCouponInternal(idx, epoch, totalAmount);
    }

    /**
     * @notice Internal coupon payment entry.
     * @param idx          Tranche index.
     * @param epoch        Coupon epoch index.
     * @param totalAmount  Total amount to distribute.
     */
    function _payCouponInternal(
        uint256 idx,
        uint32  epoch,
        uint256 totalAmount
    ) internal {
        require(totalAmount > 0, "zero");
        Tranche storage t = _tranches[idx];
        require(t.status == TrancheStatus.ACTIVE, "bad status");
        require(epoch < t.coupons.length, "epoch!");
        CouponSchedule storage c = t.coupons[epoch];
        require(!c.paid, "paid");
        require(block.timestamp >= c.payDate, "early");
        uint256 snapId = t.token.snapshot();
        uint256 supply = t.token.totalSupplyAt(t.classId, t.nonceId, snapId);
        require(supply > 0,"redeemed");
        
        t.couponToken.safeTransferFrom(_msgSender(), address(this), totalAmount);

        c.paid = true;
        c.totalPaid = totalAmount;
        c.snapshotId = snapId;
        
        c.perUnit = totalAmount / supply;
        t.outstandingCoupon += totalAmount;

        if(epoch == t.nextUnpaid){while(t.nextUnpaid < t.coupons.length && t.coupons[t.nextUnpaid].paid){++t.nextUnpaid;}}
        emit CouponPaid(idx, epoch, totalAmount);
    }

    /**
     * @notice Decrease `requiredPrincipal` by `paid`, saturating at zero.
     * @param t     Tranche storage ref.
     * @param paid  Amount to deduct.
     */
    function _decreaseRequired(Tranche storage t, uint256 paid) private {
        if (t.requiredPrincipal == 0) return;
        if (paid >= t.requiredPrincipal) {
            t.requiredPrincipal = 0;
            return;
        }
        unchecked { t.requiredPrincipal -= paid; }
    }

    /* ───────────── Investor: claim coupon ───────────── */

    /**
     * @notice Claim coupon for an epoch based on snapshot balance.
     * @param idx    Tranche index.
     * @param epoch  Coupon epoch index.
     *
     * @dev Uses `balanceOfAt(holder, ..., snapshotId)` × `perUnit`.
     * @custom:reverts epoch!    if out of range
     * @custom:reverts not paid  if epoch not yet paid
     * @custom:reverts claimed   if holder already claimed
     * @custom:reverts zero      if computed amount is zero
     * @custom:reverts exceeds   if `claimed + amt > totalPaid`
     */
    function claimCoupon(
        uint256 idx,
        uint32  epoch
    ) external nonReentrant whenNotPaused
    {
        Tranche storage t = _tranches[idx];
        require(epoch < t.coupons.length, "epoch!");
        
        CouponSchedule storage c = t.coupons[epoch];
        require(c.paid, "not paid");
        require(!t.claimed[epoch][_msgSender()], "claimed");

        uint256 bal = t.token.balanceOfAt(_msgSender(), t.classId, t.nonceId, c.snapshotId);
        uint256 amt = _mulUint(bal, c.perUnit);
        
        require(amt > 0, "zero");
        require(c.claimed + amt <= c.totalPaid, "exceeds");
        
        c.claimed += amt;
        t.outstandingCoupon -= amt;
        t.claimed[epoch][_msgSender()] = true;
        t.couponToken.safeTransfer(_msgSender(), amt);

        emit CouponClaimed(idx, epoch, _msgSender(), amt);
    }

    /* ───────────── Call & Put ───────────── */

    /**
     * @notice Issuer notifies call; after notice period holders can execute call.
     * @param idx Tranche index.
     *
     * @dev Sets `status = CALLED` and records `callNoticeTime = now`.
     * @custom:reverts not ACTIVE via `onlyActive`
     */
    function notifyCall(uint256 idx) external onlyRole(MINTER_ROLE) onlyActive(idx) whenNotPaused {
        Tranche storage t = _tranches[idx];
        t.callNoticeTime = uint64(block.timestamp);
        t.status         = TrancheStatus.CALLED;
        emit CallNotified(idx);
    }

    /* ───────── safeMul helpers (internal/private) ───────── */

    /**
     * @notice Overflow-checked multiplication.
     */
    function _mulUint(uint256 a, uint256 b) internal pure returns (uint256 c) {
        if (a==0 || b==0) return 0;
        c = a * b;
        require(c / a == b, "mul overflow");
    }

    /**
     * @notice Multiply `x` by a bps fraction (`bps / 10_000`) safely.
     */
    function _mulBps(uint256 x, uint256 bps) internal pure returns (uint256) {
        return _mulUint(x, bps) / BPS_DENOM;
    }

    /**
     * @notice Execute the issuer’s call: holder surrenders `amount` units and receives call price.
     * @param idx     Tranche index.
     * @param amount  Units to call (burn).
     *
     * @dev
     * - Requires tranche CALLED and call notice satisfied.
     * - Pays `principalPerUnit * callPriceBps / 10_000` per unit from `principalPool`.
     * - Burns holder’s debt units and transfers principal token.
     *
     * @custom:reverts not called       if status != CALLED
     * @custom:reverts notice           if call notice period not elapsed
     * @custom:reverts PRINCIPAL_INSUFF if principalPool < pay
     */
    function executeCall(uint256 idx, uint256 amount)
        external nonReentrant whenNotPaused nonZero(amount) principalCovered(idx) noSameBlockFund(idx)
    {
        Tranche storage t = _tranches[idx];
        require(t.status == TrancheStatus.CALLED, "not called");
        require(block.timestamp >= t.callNoticeTime + t.callNoticePeriod, "notice");

        uint256 principal = _mulUint(amount, t.principalPerUnit);
        uint256 pay       = _mulBps(principal, t.callPriceBps);

        // TODO: check balance before do this.
        require(t.principalPool >= pay, "PRINCIPAL_INSUFF");
        t.principalPool -= pay;
        _decreaseRequired(t, pay);
        
        t.token.burn(_msgSender(), t.classId, t.nonceId, amount);
        t.principalToken.safeTransfer(_msgSender(), pay);
        
        emit Called(idx, _msgSender(), amount, pay);
    }

    /**
     * @notice Holder files a put notice (must hold > 0 units).
     * @param idx Tranche index.
     *
     * @dev Records per-holder timestamp. Execution allowed after notice period.
     * @custom:reverts no balance if holder has zero balance at filing time
     */
    function givePutNotice(uint256 idx) external onlyActive(idx) whenNotPaused {
        Tranche storage t = _tranches[idx];
        require(t.token.balanceOf(_msgSender(), t.classId, t.nonceId) > 0, "no balance");
        t.putNotice[_msgSender()] = uint64(block.timestamp);
        emit PutNotified(idx, _msgSender());
    }

    /**
     * @notice Execute put after notice period: holder receives `putPriceBps` × principal per unit.
     * @param idx     Tranche index.
     * @param amount  Units to put (burn).
     *
     * @dev Clears notice if holder’s remaining balance becomes zero.
     * @custom:reverts no notice        if holder did not file notice
     * @custom:reverts notice           if notice period not elapsed
     * @custom:reverts PRINCIPAL_INSUFF if principalPool < pay
     */
    function exercisePut(uint256 idx, uint256 amount)
        external nonReentrant whenNotPaused nonZero(amount) principalCovered(idx) noSameBlockFund(idx)
    {
        Tranche storage t = _tranches[idx];
        uint64 notice = t.putNotice[_msgSender()];
        require(notice != 0, "no notice");
        require(block.timestamp >= notice + t.putNoticePeriod, "notice");

        uint256 principal = _mulUint(amount, t.principalPerUnit);
        uint256 pay       = _mulBps(principal, t.putPriceBps);
        
        require(t.principalPool >= pay, "PRINCIPAL_INSUFF");
        t.principalPool -= pay;
        _decreaseRequired(t, pay);

        t.token.burn(_msgSender(), t.classId, t.nonceId, amount);
        t.principalToken.safeTransfer(_msgSender(), pay);

        if (t.token.balanceOf(_msgSender(), t.classId, t.nonceId) == 0) {
            delete t.putNotice[_msgSender()];
        }
        emit PutExecuted(idx, _msgSender(), amount);
    }

    /* ───────────── Default detection ───────────── */

    /**
     * @notice Mark tranche as DEFAULTED if the next unpaid coupon exceeds grace.
     * @param idx Tranche index.
     *
     * @dev No-op if not ACTIVE or all coupons already paid.
     */
    function checkDefault(uint256 idx) external whenNotPaused {
        Tranche storage t = _tranches[idx];
        if (t.status != TrancheStatus.ACTIVE) return;

        uint32 ep = t.nextUnpaid;
        if (ep >= t.coupons.length) return;

        CouponSchedule storage c = t.coupons[ep];
        if (!c.paid && block.timestamp > c.payDate + COUPON_GRACE) {
            t.status = TrancheStatus.DEFAULTED;
            emit Defaulted(idx, ep);
        }
    }

    /**
     * @notice Notify that debt token total supply changed (e.g., external redemption/mint).
     * @param idx Tranche index.
     *
     * @dev Adjusts `requiredPrincipal` by `principalPerUnit * Δunits` and updates `cachedSupply`.
     * @custom:reverts NO_CHANGE if current equals cached
     * @custom:reverts UNDERFLOW if a negative adjustment would underflow requiredPrincipal
     */
    function notifySupplyChange(uint256 idx) external onlyRole(MINTER_ROLE) {
        Tranche storage t = _tranches[idx];

        uint256 cur = t.token.totalSupply(t.classId, t.nonceId);
        uint256 prev = t.cachedSupply;
        require(cur != prev, "NO_CHANGE");

        int256 dUnits = int256(cur) - int256(prev);
        int256 dPrincipal = int256(t.principalPerUnit) * dUnits;

        if (dPrincipal > 0) {
            t.requiredPrincipal += uint256(dPrincipal);
        } else {
            uint256 dec = uint256(-dPrincipal);
            require(dec <= t.requiredPrincipal, "UNDERFLOW");
            unchecked { t.requiredPrincipal -= dec; }
        }
        t.cachedSupply = cur;

        emit SupplyAdjusted(idx, dUnits, dPrincipal);
    }

    /* ───────────── Redemption at maturity ───────────── */

    /**
     * @notice Redeem principal at/after maturity (ACTIVE/PUT_NOTICE).
     * @param idx     Tranche index.
     * @param amount  Units to redeem (burn).
     *
     * @dev Pays `principalPerUnit * amount` from `principalPool` and burns debt units.
     * @custom:reverts bad status         if not ACTIVE or PUT_NOTICE
     * @custom:reverts not matured        if now < maturity
     * @custom:reverts overflow           if amount * principalPerUnit would overflow
     * @custom:reverts PRINCIPAL_INSUFF   if principalPool < pay
     */
    function redeemAtMaturity(uint256 idx, uint256 amount)
        external nonReentrant whenNotPaused nonZero(amount) principalCovered(idx) noSameBlockFund(idx)
    {
        Tranche storage t = _tranches[idx];
        require(
            t.status == TrancheStatus.ACTIVE || t.status == TrancheStatus.PUT_NOTICE,
            "bad status"
        );
        require(block.timestamp >= t.maturity, "not matured");
        require(amount <= type(uint256).max / t.principalPerUnit, "overflow");

        uint256 pay = _mulUint(amount, t.principalPerUnit);
        
        require(t.principalPool >= pay, "PRINCIPAL_INSUFF");
        t.principalPool -= pay;
        _decreaseRequired(t, pay);

        t.token.burn(_msgSender(), t.classId, t.nonceId, amount);
        t.principalToken.safeTransfer(_msgSender(), pay);
        emit PrincipalRedeemed(idx, _msgSender(), amount);
    }

    /* ───────────── Close tranche ───────────── */

    /**
     * @notice Close tranche at/after maturity; optionally sweep residuals after grace.
     * @param idx  Tranche index.
     * @param to   Recipient of residual funds (must be non-zero).
     *
     * @dev
     * - Clears active registry flag.
     * - If now ≥ maturity + SWEEP_GRACE: sweep coupon residuals (careful when coupon/principal tokens coincide).
     * - Else: require all coupons fully claimed (`outstandingCoupon == 0`).
     * - Transfers remaining principalPool to `to`.
     *
     * @custom:reverts zero to       if `to == address(0)`
     * @custom:reverts not matured   if now < maturity
     * @custom:reverts defaulted     if tranche in DEFAULTED status
     * @custom:reverts coupon pending if not all coupons claimed and within sweep grace
     */
    function closeTranche(uint256 idx, address to) external nonReentrant onlyRole(MINTER_ROLE) {
        require(to != address(0), "zero to");
        Tranche storage t = _tranches[idx];
        require(block.timestamp >= t.maturity, "not matured");
        require(t.status != TrancheStatus.DEFAULTED, "defaulted");
        t.status = TrancheStatus.MATURED;

        bytes32 key = keccak256(abi.encode(bytes1(0x01), t.token, bytes1(0x02), t.classId, bytes1(0x03), t.nonceId));
        _activeRegistry[key] = false;

        if (block.timestamp >= t.maturity + SWEEP_GRACE) {
            // After grace: sweep all residual obligations for this tranche only.
            uint256 sweepAmt = t.outstandingCoupon; // includes both unclaimed and dust
            if (sweepAmt != 0) {
                t.outstandingCoupon = 0;
                t.couponToken.safeTransfer(to, sweepAmt);
            }
        } else {
            // Before grace: allow close only when the remainder is dust-only.
            uint256 dust = _unallocatableRemainder(t);
            require(t.outstandingCoupon <= dust, "coupon pending");
            // Early sweep the dust so operators don't have to remember a later sweep.
            uint256 sweepAmt = t.outstandingCoupon; // equals dust at this moment
            if (sweepAmt != 0) {
                t.outstandingCoupon = 0;
                t.couponToken.safeTransfer(to, sweepAmt);
            }
        }

        // Transfer remaining principal pool for this tranche.
        uint256 prinBal = t.principalPool;
        if (prinBal != 0) t.principalToken.safeTransfer(to, prinBal);

        emit TrancheClosed(idx, to);
    }

    /**
     * @notice Fund tranche principal pool (issuer).
     * @param idx     Tranche index.
     * @param amount  Principal token amount to deposit.
     *
     * @dev Records `_lastFundBlock[idx] = block.number` to enforce payout delay.
     * @custom:reverts zero if amount == 0
     */
    function depositPrincipal(uint256 idx, uint256 amount)
        external onlyRole(MINTER_ROLE) nonReentrant trancheOpen(idx)
    {
        Tranche storage t = _tranches[idx];
        require(amount > 0, "zero");
        t.principalToken.safeTransferFrom(_msgSender(), address(this), amount);
        t.principalPool += amount;

        _lastFundBlock[idx] = uint64(block.number);
        
        emit PrincipalFunded(idx, amount);
    }

    /// @dev Sum of unallocatable dust across all paid coupons of a tranche.
    function _unallocatableRemainder(Tranche storage t) private view returns (uint256 rem) {
        uint256 len = t.coupons.length;
        for (uint32 ep = 0; ep < len; ++ep) {
            CouponSchedule storage c = t.coupons[ep];
            if (!c.paid) continue;

            // Snapshot supply at payment time
            uint256 supplyAt = t.token.totalSupplyAt(t.classId, t.nonceId, c.snapshotId);

            // Distributable = perUnit * supplyAt (floor math)
            uint256 distributable = _mulUint(c.perUnit, supplyAt);

            // Dust = totalPaid - distributable (if any)
            if (c.totalPaid > distributable) {
                unchecked { rem += (c.totalPaid - distributable); }
            }
        }
    }

    /* ───────────── Bitmap helpers ───────────── */

    /**
     * @notice Check if `owner` claimed a coupon epoch.
     * @param t    Tranche storage ref.
     * @param ep   Epoch index.
     * @param owner Holder address.
     * @return bool Whether claimed.
     */
    function _isClaimed(Tranche storage t, uint32 ep, address owner) internal view returns (bool) {
        return t.claimed[ep][owner];
    }

    /* ───────────── Views ───────────── */

    /**
     * @notice Number of tranches created.
     * @return uint256 Length of `_tranches`.
     */
    function tranchesLength() external view returns (uint256) { return _tranches.length; }

    /**
     * @notice Read key tranche metadata.
     * @param idx Tranche index.
     * @return token            Debt token address.
     * @return classId          Class id.
     * @return nonceId          Nonce id.
     * @return principalToken   Principal ERC20 address.
     * @return principalPerUnit Principal per debt unit.
     * @return couponToken      Coupon ERC20 address.
     * @return maturity         Maturity timestamp.
     * @return status           Tranche status enum.
     * @return callPriceBps     Call price bps.
     * @return putPriceBps      Put price bps.
     */
    function trancheInfo(uint256 idx) external view returns (
        address token,
        uint256 classId,
        uint256 nonceId,
        address principalToken,
        uint256 principalPerUnit,
        address couponToken,
        uint64  maturity,
        TrancheStatus status,
        uint64 callPriceBps,
        uint64 putPriceBps
    ) {
        Tranche storage t = _tranches[idx];
        return (
            address(t.token),
            t.classId,
            t.nonceId,
            address(t.principalToken),
            t.principalPerUnit,
            address(t.couponToken),
            t.maturity,
            t.status,
            t.callPriceBps,
            t.putPriceBps
        );
    }

    /**
     * @notice Number of coupon epochs for a tranche.
     * @param idx Tranche index.
     * @return uint256 Count of coupons.
     */
    function couponCount(uint256 idx) external view returns (uint256) {
        return _tranches[idx].coupons.length;
    }

    /**
     * @notice Return coupon epoch metadata (without snapshot fields).
     * @param idx Tranche index.
     * @param ep  Epoch index.
     * @return payDate   Due timestamp.
     * @return rateBps   Informational rate (bps).
     * @return paid      Whether paid.
     * @return totalPaid Total amount provisioned.
     * @return claimed   Total amount claimed so far.
     */
    function couponMeta(uint256 idx, uint32 ep) external view returns (
        uint64 payDate,
        uint256 rateBps,
        bool paid,
        uint256 totalPaid,
        uint256 claimed
    ) {
        CouponSchedule storage c = _tranches[idx].coupons[ep];
        return (c.payDate, c.rateBps, c.paid, c.totalPaid, c.claimed);
    }

    /**
     * @notice Public view to check if `owner` claimed epoch `ep` for tranche `idx`.
     * @return bool Whether claimed.
     */
    function isClaimed(uint256 idx, uint32 ep, address owner) external view returns (bool) {
        return _isClaimed(_tranches[idx], ep, owner);
    }

    /* ───────────── Pause ───────────── */

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

    /*────────────────────── UUPS auth ────────────────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /* ───────────── Storage gap ───────────── */

    /**
     * @dev Reserved storage to allow future variable additions while preserving layout.
     */
    uint256[43] private __gap;
}

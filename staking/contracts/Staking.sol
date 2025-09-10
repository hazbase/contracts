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

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC165.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import "@openzeppelin/contracts/interfaces/IERC721.sol";
import "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import "@openzeppelin/contracts/interfaces/IERC1155.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ───── Whitelist registry (optional) ───── */
interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

/**
 * @title Staking
 *
 * @notice
 * - Purpose: Unified staking pool supporting **ERC20 / ERC721 / ERC1155** deposits, with:
 *   * Linear reward emissions (rate/sec for a fixed `rewardsDuration`),
 *   * Per-user positions (shares + rewardDebt) and global `accRewardPerShare`,
 *   * Optional deposit fee and recipient treasury, cooldown between stakes, and whitelist (KYC),
 *   * Scheduled actions (admin-triggered) for automated interactions (e.g., refill/reclaim),
 *   * UUPS upgradeability, ERC-2771 meta-transactions, and pausability.
 *
 * - Reward model:
 *   * `deposit()` loads `reservedReward` and (re)computes `rewardRate` over `rewardsDuration`,
 *     extending `finishAt`. `updatePool` accrues rewards into `accRewardPerShare` on interaction.
 *   * On stake/unstake/claim, pending rewards are paid out from `reservedReward`, capped by availability.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Emission invariants: reward tokens to be emitted are pre-funded into the contract by `deposit()`.
 * - Precision: rewards accrue in 1e18 precision; payouts are rounded via `_round()` to `rewardPrecision`.
 * - Liquidity guard: withdrawing staked **rewardToken** checks `_availableLiquidity()` to avoid “recycle” drain.
 * - Fees: optional per-asset burning/treasury in ERC20/1155 stake paths; no fees on ERC721.
 * - Access control: `ADMIN_ROLE` controls economics; `MINTER_ROLE` can set whitelist; `PAUSER_ROLE` pauses.
 */

contract Staking is
    Initializable,
    ReentrancyGuardUpgradeable,
    IERC721Receiver,
    IERC1155Receiver,
    RolesCommonUpgradeable,
    PausableUpgradeable,
    ERC2771ContextUpgradeable,
    UUPSUpgradeable
{
    using SafeERC20 for IERC20;

    /*─────────────────────── Pool & reward configuration ─────────────────────*/

    /// @notice ERC20 token used to pay rewards (immutable after init).
    IERC20  public rewardToken;

    /// @notice Emission rate of `rewardToken` per second (set by `deposit()`).
    uint256 public rewardRate;

    /// @notice UNIX timestamp when linear rewards stop (updated on `deposit()`).
    uint256 public finishAt;

    /// @notice Remaining rewards earmarked for payout (decreases on user claims).
    uint256 public reservedReward;

    /// @notice Emission duration per `deposit()` cycle (seconds).
    uint64  public rewardsDuration;

    /// @notice Rounding precision for user-visible payouts (≤ 18).
    uint8   public rewardPrecision = 18;

    /*──────────────────────────── Staking state ────────────────────────────*/

    /**
     * @dev Per-user position for a (token, tokenId).
     * - `shares`: normalized shares (ERC20: amount; ERC721: count; ERC1155: units).
     * - `rewardDebt`: accumulator checkpoint (shares * accRewardPerShare / 1e18).
     */
    struct Position {
        uint256 shares;
        uint256 rewardDebt;
    }

    /// @notice Optional on-chain KYC registry.
    IWhitelist public whitelist;

    /// @dev tokenAddress => tokenId (0 for ERC20) => user => position
    mapping(address => mapping(uint256 => mapping(address => Position))) private _positions;

    /// @notice Arrowlist (allowlist) of tokens permitted for staking.
    mapping(address => bool) public isArrowed;

    /// @notice Current total shares across all stakers.
    uint256 public totalShares;

    /// @notice Accumulated reward per share (scaled by 1e18).
    uint256 public accRewardPerShare;

    /// @notice Last timestamp the pool was updated (bounded by `finishAt`).
    uint256 public lastUpdate;

    /// @notice Stake cooldown in seconds (0 ⇒ disabled).
    uint64  public cooldownSecs;

    /// @notice Deposit fee in basis points (0 ⇒ free, 100 = 1%).
    uint16  public depositFeeBps;

    /// @notice Recipient of deposit fees (address(0) -> burn).
    address public feeTreasury;

    /// @notice Last stake time per user (enforces cooldown).
    mapping(address => uint256) public lastStakeAt;

    /*──────────────────────────── Scheduled actions ─────────────────────────*/

    /**
     * @dev Admin-scheduled action executed via `executeAction`.
     * - `executeAfter` : earliest timestamp to run.
     * - `target`       : destination contract.
     * - `value`        : ETH value to send with call.
     * - `data`         : calldata (must include 4-byte selector).
     * - `recurring`    : if true, reschedules by `interval` on success.
     * - `interval`     : recurrence interval in seconds.
     * - `executed`     : set true for one-shot after execution (or if recurring fails once).
     */
    struct Action {
        uint64  executeAfter;
        address target;
        uint256 value;
        bytes   data;
        bool    recurring;
        uint64  interval;
        bool    executed;
    }
    Action[] private _actions;

    /*────────────────────────────── Events ──────────────────────────────*/

    event Staked  (address indexed user, address indexed token, uint256 id, uint256 amount);
    event Unstaked(address indexed user, address indexed token, uint256 id, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event ActionScheduled(uint256 indexed id, address indexed target, bytes4 selector, uint64 executeAfter, bool recurring);
    event ActionExecuted (uint256 indexed id, address indexed target, bool success);
    event CooldownUpdated(uint64 _secs);
    event DepositFeeUpdated(uint16 _bps, address _treasury);
    event TokenArrowed(address indexed token, bool allowed);

    /*──────────────────────────── Initializer ───────────────────────────*/

    /**
     * @notice Disable initializers for the implementation (UUPS pattern).
     */
    constructor() { _disableInitializers(); }
    
    /**
     * @notice Initialize the staking pool.
     * @param admin             Admin address (granted roles via RolesCommon).
     * @param _rewardToken      ERC20 used for rewards.
     * @param _duration         Emission duration for each `deposit()` cycle.
     * @param _cooldownSecs     Stake cooldown in seconds (0 to disable).
     * @param _depositFeeBps    Deposit fee in bps (0..500; 500 = 5%).
     * @param _feeTreasury      Recipient of deposit fees (address(0) ⇒ burn).
     * @param _initialArrowlist List of token addresses initially allowed for staking.
     * @param forwarders        Trusted ERC-2771 forwarders for meta-transactions.
     *
     * @dev Sets initial emission state to 0 and finishAt=now; roles and meta-tx set up.
     *
     * @custom:reverts bad params if `_rewardToken == 0` or `_duration == 0`
     */
    function initialize(
        address admin,
        address _rewardToken,
        uint64  _duration,
        uint64  _cooldownSecs,
        uint16  _depositFeeBps,
        address _feeTreasury,
        address[] calldata _initialArrowlist,
        address[] calldata forwarders
    ) external initializer {
        require(_rewardToken != address(0) && _duration > 0, "bad params");

        __AccessControl_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __Pausable_init();
        __RolesCommon_init(admin);

        rewardToken = IERC20(_rewardToken);
        rewardsDuration = _duration;
        finishAt    = block.timestamp;
        lastUpdate  = block.timestamp;
        rewardRate  = 0;

        cooldownSecs   = _cooldownSecs;
        depositFeeBps  = _depositFeeBps;
        feeTreasury    = _feeTreasury;

        for (uint i = 0; i < _initialArrowlist.length; ++i) {
            isArrowed[_initialArrowlist[i]] = true;
        }
    }

    /*──────────────────────────── Admin economics ───────────────────────*/

    /**
     * @notice Fund rewards and (re)start emission.
     * @param amount Amount of `rewardToken` to deposit for emissions.
     *
     * @dev
     * - Pulls `amount` from caller (ADMIN_ROLE) and increases `reservedReward`.
     * - Computes leftover = remaining time * current `rewardRate` if emission still active.
     * - Sets `rewardRate = (amount + leftover) / rewardsDuration`, updates `finishAt` and `lastUpdate`.
     *
     * @custom:reverts zero if `amount == 0`
     * @custom:reverts rate=0 if computed `rewardRate == 0`
     */
    function deposit(uint256 amount)
        external
        onlyRole(ADMIN_ROLE)
        nonReentrant
        whenNotPaused
        updatePool
    {
        require(amount > 0, "zero");

        rewardToken.safeTransferFrom(_msgSender(), address(this), amount);
        reservedReward += amount;

        uint256 leftover = 0;
        if (block.timestamp < finishAt) {
            uint256 remaining = finishAt - block.timestamp;
            leftover = remaining * rewardRate;
        }

        rewardRate = (amount + leftover) / rewardsDuration;
        require(rewardRate > 0, "rate=0");

        finishAt  = block.timestamp + rewardsDuration;
        lastUpdate = block.timestamp;
    }

    /**
     * @notice Withdraw leftover rewards back to `to` after emission ended.
     * @param to Address to receive leftover `rewardToken`.
     *
     * @dev Only ADMIN_ROLE and only when `block.timestamp > finishAt`. Resets `reservedReward` to 0.
     *
     * @custom:reverts period active if emission window not finished
     * @custom:reverts none          if no leftover in `reservedReward`
     */
    function withdraw(address to)
        external
        nonReentrant
        whenNotPaused
        onlyRole(ADMIN_ROLE)
    {
        require(block.timestamp > finishAt, "period active");
        uint256 leftover = reservedReward;
        require(leftover > 0, "none");

        reservedReward = 0;
        rewardToken.safeTransfer(to, leftover);
    }

    /**
     * @notice Set stake cooldown in seconds (0 disables).
     * @param _secs Cooldown duration.
     */
    function setCooldown(uint64 _secs) external whenNotPaused onlyRole(ADMIN_ROLE) {
        cooldownSecs = _secs;
        emit CooldownUpdated(_secs);
    }

    /**
     * @notice Set rounding precision (≤ 18) for user-visible rewards.
     * @param p Number of decimals retained when rounding down payouts.
     *
     * @custom:reverts too large if `p > 18`
     */
    function setRewardPrecision(uint8 p) external whenNotPaused onlyRole(ADMIN_ROLE) {
        require(p <= 18, "too large");
        rewardPrecision = p;
    }

    /**
     * @notice Configure deposit fee and fee recipient.
     * @param _bps      Fee in basis points (0..500).
     * @param _treasury Recipient of fees (address(0) ⇒ burn).
     *
     * @dev Emits `DepositFeeUpdated`.
     *
     * @custom:reverts max 5 % if `_bps > 500`
     */
    function setDepositFee(uint16 _bps, address _treasury)
        external
        whenNotPaused
        onlyRole(ADMIN_ROLE)
    {
        require(_bps <= 500, "max 5 %");
        depositFeeBps = _bps;
        feeTreasury   = _treasury;
        emit DepositFeeUpdated(_bps, _treasury);
    }

    /**
     * @notice Allow or disallow a token for staking (arrowlist).
     * @param token   Asset address.
     * @param allowed True to allow, false to disallow.
     *
     * @dev Emits `TokenArrowed`.
     */
    function setArrowlist(address token, bool allowed)
        external
        whenNotPaused
        onlyRole(ADMIN_ROLE)
    {
        isArrowed[token] = allowed;
        emit TokenArrowed(token, allowed);
    }

    /**
     * @notice Enforce whitelist (KYC) check for `sender` if a registry is configured.
     * @param sender Address to check.
     *
     * @custom:reverts SENDER_NOT_WHITELISTED if registry exists and sender is not whitelisted
     */
    function _enforceWL(address sender) internal view {
        if (address(whitelist) == address(0)) return;         // registry not set ⟹ no checks
        require(whitelist.isWhitelisted(sender), "SENDER_NOT_WHITELISTED");
    }

    /*────────────────────────── Whitelist admin ─────────────────────────*/

    /**
     * @notice Set (or clear) the whitelist registry.
     * @param registry Whitelist contract address (or 0 to disable checks).
     *
     * @dev Only MINTER_ROLE.
     */
    function setWhitelist(address registry) external whenNotPaused onlyRole(MINTER_ROLE) {
        whitelist = IWhitelist(registry);
    }

    /*────────────────────────── Modifiers (internal) ─────────────────────*/

    /**
     * @notice Accrue rewards into `accRewardPerShare` up to now (bounded by `finishAt`).
     *
     * @dev Updates `lastUpdate` to `min(now, finishAt)` and increases `accRewardPerShare`
     *      if there are shares and time has advanced.
     */
    modifier updatePool() {
        uint256 end = block.timestamp < finishAt ? block.timestamp : finishAt;
        if (end > lastUpdate && totalShares > 0) {
            uint256 reward = (end - lastUpdate) * rewardRate;
            accRewardPerShare += (reward * 1e18) / totalShares;
        }
        lastUpdate = end;
        _;
    }

    /**
     * @notice Gate functions to only whitelisted callers when registry is set.
     */
    modifier onlyWhitelisted() {
        require(address(whitelist) == address(0) || whitelist.isWhitelisted(_msgSender()), "addr not whitelisted");
        _;
    }

    /*────────────────────────── Private helpers ─────────────────────────*/

    /**
     * @notice Compute pending (unrounded) reward for a position at current accumulator.
     * @param p Position snapshot (shares + rewardDebt).
     * @return uint256 Raw pending reward (no rounding).
     */
    function _pending(Position memory p) private view returns (uint256) {
        return (p.shares * accRewardPerShare) / 1e18 - p.rewardDebt;
    }

    /**
     * @notice Compute available reward liquidity (= on-chain balance − reservedReward).
     */
    function _availableLiquidity() private view returns (uint256) {
        return rewardToken.balanceOf(address(this)) - reservedReward;
    }

    /**
     * @notice Core position update (stake/unstake) and on-the-fly reward payout.
     * @param token  Asset address.
     * @param id     Token id (0 for ERC20).
     * @param amount Shares delta (positive for stake, positive value passed with `add=false` for unstake).
     * @param add    True for stake, false for unstake.
     * @return pending Amount paid out (after rounding & cap), emitted as `RewardClaimed` if > 0.
     *
     * @dev
     * - Pays out `_pending` (rounded to `rewardPrecision`) up to `reservedReward`.
     * - Adjusts user shares and global `totalShares`.
     * - Sets `rewardDebt = shares * accRewardPerShare / 1e18`.
     * - Emits `RewardClaimed` if a payout occurred.
     *
     * @custom:reverts insufficient if unstake `amount` exceeds user shares
     */
    function _updatePosition(
        address token,
        uint256 id,
        uint256 amount,
        bool    add
    ) private returns (uint256 pending) {
        Position storage pos = _positions[token][id][_msgSender()];
        pending = _round(_pending(pos));

        if (pending > 0 && reservedReward > 0) {
            if (pending > reservedReward) pending = reservedReward;
    
            reservedReward -= pending;
            rewardToken.safeTransfer(_msgSender(), pending);
            emit RewardClaimed(_msgSender(), pending);
        }

        if (add) {
            pos.shares += amount;
            totalShares += amount;
        } else {
            require(pos.shares >= amount, "insufficient");
            pos.shares -= amount;
            totalShares -= amount;
        }
        pos.rewardDebt = (pos.shares * accRewardPerShare) / 1e18;
    }

    /*────────────────────────── ERC20 stake / unstake ───────────────────*/

    /**
     * @notice Stake ERC20 tokens.
     * @param token  ERC20 to stake (must be arrowlisted).
     * @param amount Amount to stake (>0). A deposit fee may be charged.
     *
     * @dev
     * - Enforces optional cooldown and whitelist.
     * - If `depositFeeBps != 0`, moves fee to `feeTreasury` (or burns to address(0)) then stakes the net.
     * - Transfers `net` to the pool and updates position.
     * - Emits `Staked`.
     */
    function stakeERC20(address token, uint256 amount) external onlyWhitelisted nonReentrant updatePool {
        require(isArrowed[token], "token not allowed");
        require(amount > 0, "0");
        
        if (cooldownSecs != 0) {
            require(
                block.timestamp >= lastStakeAt[_msgSender()] + cooldownSecs,
                "cooldown"
            );
            lastStakeAt[_msgSender()] = block.timestamp;
        }

        uint256 net = amount;
        if (depositFeeBps != 0) {
            uint256 fee = (amount * depositFeeBps) / 10_000;
            net = amount - fee;

            if (feeTreasury == address(0)) {
                IERC20(token).safeTransferFrom(_msgSender(), address(0), fee); // burn
            } else {
                IERC20(token).safeTransferFrom(_msgSender(), feeTreasury, fee);
            }
        }
        
        IERC20(token).safeTransferFrom(_msgSender(), address(this), net); // hooks first
        _updatePosition(token, 0, net, true);
        emit Staked(_msgSender(), token, 0, net);
    }

    /**
     * @notice Unstake previously staked ERC20 tokens.
     * @param token  ERC20 address.
     * @param amount Amount to unstake.
     *
     * @dev If unstaking the `rewardToken` itself, ensures on-chain liquidity is sufficient.
     *      Updates position and transfers `amount` back. Emits `Unstaked`.
     *
     * @custom:reverts liquidity shortfall when unstaking rewardToken beyond available liquidity
     */
    function unstakeERC20(address token, uint256 amount) external nonReentrant updatePool {
        if (token == address(rewardToken)) {
            require(_availableLiquidity() >= amount, "liquidity shortfall");
        }
        
        _updatePosition(token, 0, amount, false);
        IERC20(token).safeTransfer(_msgSender(), amount);
        emit Unstaked(_msgSender(), token, 0, amount);
    }

    /*────────────────────────── ERC721 stake / unstake ──────────────────*/

    /**
     * @notice Stake one ERC721 token.
     * @param token   ERC721 collection (must be arrowlisted).
     * @param tokenId Token id to stake.
     *
     * @dev Enforces whitelist/cooldown. Transfers the NFT to the pool, updates position, emits `Staked`.
     */
    function stakeERC721(address token, uint256 tokenId) external onlyWhitelisted nonReentrant updatePool {
        require(isArrowed[token], "token not allowed");
        if (cooldownSecs != 0) {
            require(
                block.timestamp >= lastStakeAt[_msgSender()] + cooldownSecs,
                "cooldown"
            );
            lastStakeAt[_msgSender()] = block.timestamp;
        }
        IERC721(token).safeTransferFrom(_msgSender(), address(this), tokenId);
        _updatePosition(token, tokenId, 1, true);
        emit Staked(_msgSender(), token, tokenId, 1);
    }

    /**
     * @notice Unstake one ERC721 token.
     * @param token   ERC721 collection.
     * @param tokenId Token id to unstake.
     *
     * @dev Updates position and transfers the NFT back. Emits `Unstaked`.
     */
    function unstakeERC721(address token, uint256 tokenId) external nonReentrant updatePool {
        _updatePosition(token, tokenId, 1, false);
        IERC721(token).safeTransferFrom(address(this), _msgSender(), tokenId);
        emit Unstaked(_msgSender(), token, tokenId, 1);
    }

    /*────────────────────────── ERC1155 stake / unstake ─────────────────*/

    /**
     * @notice Stake ERC1155 tokens.
     * @param token  ERC1155 collection (must be arrowlisted).
     * @param id     Token id to stake.
     * @param amount Units to stake (>0). A deposit fee may be charged in units.
     *
     * @dev Enforces whitelist/cooldown. Burns or transfers fee in units, stakes net, updates position.
     *      Emits `Staked`.
     */
    function stakeERC1155(address token, uint256 id, uint256 amount) external onlyWhitelisted nonReentrant updatePool {
        require(isArrowed[token], "token not allowed");
        require(amount > 0, "0");
        
        if (cooldownSecs != 0) {
            require(
                block.timestamp >= lastStakeAt[_msgSender()] + cooldownSecs,
                "cooldown"
            );
            lastStakeAt[_msgSender()] = block.timestamp;
        }

        uint256 net = amount;
        if (depositFeeBps != 0) {
            uint256 fee = (amount * depositFeeBps) / 10_000;
            net = amount - fee;

            if (feeTreasury == address(0)) {
                IERC1155(token).safeTransferFrom(_msgSender(), address(0), id, fee, ""); // burn
            } else {
                IERC1155(token).safeTransferFrom(_msgSender(), feeTreasury, id, fee, "");
            }
        }

        IERC1155(token).safeTransferFrom(_msgSender(), address(this), id, net, "");
        _updatePosition(token, id, net, true);
        emit Staked(_msgSender(), token, id, net);
    }

    /**
     * @notice Unstake ERC1155 tokens.
     * @param token  ERC1155 collection.
     * @param id     Token id to unstake.
     * @param amount Units to unstake.
     *
     * @dev If unstaking `rewardToken`, checks available liquidity. Updates position and transfers back.
     *      Emits `Unstaked`.
     */
    function unstakeERC1155(address token, uint256 id, uint256 amount) external nonReentrant updatePool {
        if (token == address(rewardToken)) {
            require(_availableLiquidity() >= amount, "liquidity shortfall");
        }
        _updatePosition(token, id, amount, false);
        IERC1155(token).safeTransferFrom(address(this), _msgSender(), id, amount, "");
        emit Unstaked(_msgSender(), token, id, amount);
    }

    /**
     * @notice Round down `amt` to the configured `rewardPrecision`.
     * @param amt Raw amount in 1e18 precision.
     * @return uint256 Rounded amount.
     */
    function _round(uint256 amt) internal view returns (uint256) {
        uint256 factor = 10 ** (18 - rewardPrecision);
        return (amt / factor) * factor;
    }

    /*────────────────────────── Claim reward ─────────────────────────*/

    /**
     * @notice Claim accrued rewards for a specific (token,id) position.
     * @param token Asset address.
     * @param id    Token id (0 for ERC20).
     *
     * @dev Pays out rounded pending, updates `reservedReward` and `rewardDebt`. Emits `RewardClaimed`.
     *
     * @custom:reverts none if no pending reward after rounding
     */
    function claim(address token, uint256 id) external onlyWhitelisted nonReentrant updatePool {
        Position storage pos = _positions[token][id][_msgSender()];
        uint256 pending = _round(_pending(pos));
        require(pending > 0, "none");
        reservedReward -= pending;
        pos.rewardDebt = (pos.shares * accRewardPerShare) / 1e18;
        rewardToken.safeTransfer(_msgSender(), pending);
        emit RewardClaimed(_msgSender(), pending);
    }

    /*────────────────────────── Scheduled actions API ─────────────────────*/

    /**
     * @notice Schedule a call to `target` with `value` and `data`.
     * @param target    Destination contract (non-zero).
     * @param value     ETH value to send with the call.
     * @param data      Calldata (must include a 4-byte selector).
     * @param delay     Delay in seconds before first execution.
     * @param recurring If true, reschedule on success every `interval` seconds.
     * @param interval  Recurrence interval (required when `recurring`).
     * @return id       Newly assigned action id.
     *
     * @dev Only ADMIN_ROLE. Emits `ActionScheduled`.
     *
     * @custom:reverts target=0   if target is zero address
     * @custom:reverts no selector if `data.length < 4`
     * @custom:reverts bad interval if `recurring==true` and `interval==0`
     */
    function scheduleAction(
        address target,
        uint256 value,
        bytes calldata data,
        uint64  delay,
        bool    recurring,
        uint64  interval
    ) external onlyRole(ADMIN_ROLE) returns (uint256 id) {
        require(target != address(0), "target=0");
        require(data.length >= 4, "no selector");
        if (recurring) require(interval > 0, "bad interval");

        id = _actions.length;
        uint64 execAt = uint64(block.timestamp + delay);
        _actions.push(Action({
            executeAfter: execAt,
            target: target,
            value: value,
            data: data,
            recurring: recurring,
            interval: interval,
            executed: false
        }));
        emit ActionScheduled(id, target, bytes4(data), execAt, recurring);
    }

    /**
     * @notice Execute a scheduled action when due; updates reward accounting around the call.
     * @param id Action id to execute.
     *
     * @dev
     * - Requires `block.timestamp ≥ executeAfter` and not already executed.
     * - Target must be `rewardToken` or arrowlisted token to limit call surface.
     * - Adjusts `reservedReward` if the call changes `rewardToken` balance.
     * - Recurring: reschedules on success; one-shot: marks executed.
     * - Emits `ActionExecuted`.
     *
     * @custom:reverts id    if out-of-range
     * @custom:reverts time< if executed too early
     * @custom:reverts done  if already executed (for one-shot)
     * @custom:reverts target not whitelisted if destination is neither rewardToken nor arrowlisted
     */
    function executeAction(uint256 id) external nonReentrant updatePool {
        require(id < _actions.length, "id");
        Action storage a = _actions[id];
        require(block.timestamp >= a.executeAfter, "time<");
        require(!a.executed, "done");

        if (!(a.target == address(rewardToken) || isArrowed[a.target])) {
            revert("target not whitelisted");
        }

        uint256 beforeBal = rewardToken.balanceOf(address(this));

        (bool ok,) = a.target.call{value: a.value}(a.data);
        emit ActionExecuted(id, a.target, ok);

        uint256 afterBal  = rewardToken.balanceOf(address(this));

        if (afterBal < beforeBal) {
            uint256 delta = beforeBal - afterBal;
            reservedReward = reservedReward > delta ? reservedReward - delta : 0;
        } else if (afterBal > beforeBal) {
            reservedReward += (afterBal - beforeBal);
        }

        if (a.recurring) {
            if (ok) {
                a.executeAfter += a.interval;
            } else {
                a.executed = true;
            }
        } else {
            a.executed = true;
        }
    }

    /*────────────────────────── View helpers ───────────────────────────*/

    /**
     * @notice Compute raw (unrounded) pending reward for a user position at **current time**.
     * @param token Asset address.
     * @param id    Token id (0 for ERC20).
     * @param user  User address.
     * @return uint256 Unrounded pending reward.
     *
     * @dev Recomputes a hypothetical `_acc` reflecting accrual to `min(now, finishAt)`.
     */
    function pendingRawReward(address token, uint256 id, address user)
        public
        view
        returns (uint256)
    {
        Position memory p = _positions[token][id][user];
        uint256 _acc = accRewardPerShare;
        uint256 end  = block.timestamp < finishAt ? block.timestamp : finishAt;
        if (end > lastUpdate && totalShares > 0) {
            uint256 reward = (end - lastUpdate) * rewardRate;
            _acc += (reward * 1e18) / totalShares;
        }
        return (p.shares * _acc) / 1e18 - p.rewardDebt;   // raw (no rounding)
    }

    /**
     * @notice Compute **rounded** pending reward for a user position.
     * @param token Asset address.
     * @param id    Token id (0 for ERC20).
     * @param user  User address.
     * @return uint256 Rounded pending reward according to `rewardPrecision`.
     */
    function pendingReward(address token, uint256 id, address user)
        external
        view
        returns (uint256)
    {
        uint256 raw = pendingRawReward(token, id, user);
        return _round(raw);
    }

    /**
     * @notice Read a stored user position.
     * @param token Asset address.
     * @param id    Token id (0 for ERC20).
     * @param user  User address.
     * @return Position Stored position struct.
     */
    function position(address token, uint256 id, address user) external view returns (Position memory) {
        return _positions[token][id][user];
    }

    /**
     * @notice Number of scheduled actions.
     */
    function actionsLength() external view returns (uint256) { return _actions.length; }

    /*───────────────────── ERC721 / ERC1155 receiver hooks ─────────────────*/

    /**
     * @notice ERC721 safe transfer receiver hook.
     */
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @notice ERC1155 single transfer receiver hook.
     */
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    /**
     * @notice ERC1155 batch transfer receiver hook.
     */
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    /*────────────────────────── Pausable ─────────────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause();   }

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
     * @notice ERC165 support (merge AccessControl & receivers).
     * @param id Interface id.
     * @return bool Whether supported.
     */
    function supportsInterface(bytes4 id) public view override(AccessControlEnumerableUpgradeable, IERC165) returns (bool) {
        return id == type(IERC1155Receiver).interfaceId ||
               id == type(IERC721Receiver).interfaceId ||
               super.supportsInterface(id);
    }

    /*────────────────────────── UUPS auth ─────────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     * @param newImpl Proposed implementation address (unused by this guard).
     */
    function _authorizeUpgrade(address newImpl) internal override onlyRole(ADMIN_ROLE) {}

    /// @dev Storage gap reserved for future upgrades.
    uint256[48] private __gap;
}

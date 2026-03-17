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

// Optional whitelist registry
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

    // Pool and reward configuration

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

    // Staking state

    /// @dev Per-user position for a `(token, tokenId)` bucket.
    /// `shares` are normalized stake units and `rewardDebt` checkpoints the accumulator at the user's last interaction.
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

    // Scheduled actions

    /// @dev Admin-scheduled action executed via `executeAction`.
    /// Stores the due time, destination call, optional recurrence, and one-shot execution state.
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

    // Events

    event Staked  (address indexed user, address indexed token, uint256 id, uint256 amount);
    event Unstaked(address indexed user, address indexed token, uint256 id, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event ActionScheduled(uint256 indexed id, address indexed target, bytes4 selector, uint64 executeAfter, bool recurring);
    event ActionExecuted (uint256 indexed id, address indexed target, bool success);
    event CooldownUpdated(uint64 _secs);
    event DepositFeeUpdated(uint16 _bps, address _treasury);
    event TokenArrowed(address indexed token, bool allowed);

    // Initialization

    /// @notice Disable initializers for the implementation contract.
    constructor() { _disableInitializers(); }
    
    /// @notice Initialize the staking pool.
    /// @param admin Admin address granted hazBase shared roles.
    /// @param _rewardToken ERC20 used for rewards.
    /// @param _duration Emission duration for each `deposit()` cycle.
    /// @param _cooldownSecs Stake cooldown in seconds, where `0` disables it.
    /// @param _depositFeeBps Deposit fee in basis points.
    /// @param _feeTreasury Recipient of deposit fees, or zero to burn.
    /// @param _initialArrowlist Token addresses initially allowed for staking.
    /// @param forwarders Trusted ERC-2771 forwarders for meta-transactions.
    /// @dev Sets the pool to an idle emission state with `finishAt = lastUpdate = block.timestamp`.
    /// @custom:reverts bad params if `_rewardToken == 0` or `_duration == 0`
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

    // Admin economics

    /// @notice Fund rewards and restart or extend emissions.
    /// @param amount Amount of `rewardToken` to deposit for emissions.
    /// @dev Rolls leftover emissions into the new rate, updates `finishAt`, and increases `reservedReward`.
    /// @custom:reverts zero if `amount == 0`
    /// @custom:reverts rate=0 if the computed `rewardRate == 0`
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

    /// @notice Withdraw leftover rewards back to `to` after emissions have ended.
    /// @param to Address to receive leftover `rewardToken`.
    /// @dev Only ADMIN_ROLE may call, and only after `finishAt`. Resets `reservedReward` to zero.
    /// @custom:reverts period active if the emission window has not finished
    /// @custom:reverts none if there is no leftover in `reservedReward`
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

    /// @notice Set the stake cooldown in seconds, where `0` disables it.
    /// @param _secs Cooldown duration.
    function setCooldown(uint64 _secs) external whenNotPaused onlyRole(ADMIN_ROLE) {
        cooldownSecs = _secs;
        emit CooldownUpdated(_secs);
    }

    /// @notice Set rounding precision for user-visible rewards.
    /// @param p Number of decimals retained when rounding down payouts.
    /// @custom:reverts too large if `p > 18`
    function setRewardPrecision(uint8 p) external whenNotPaused onlyRole(ADMIN_ROLE) {
        require(p <= 18, "too large");
        rewardPrecision = p;
    }

    /// @notice Configure the deposit fee and fee recipient.
    /// @param _bps Fee in basis points.
    /// @param _treasury Recipient of fees, or zero to burn.
    /// @dev Emits `DepositFeeUpdated`.
    /// @custom:reverts max 5 % if `_bps > 500`
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

    /// @notice Allow or disallow a token for staking.
    /// @param token Asset address.
    /// @param allowed True to allow, false to disallow.
    /// @dev Emits `TokenArrowed`.
    function setArrowlist(address token, bool allowed)
        external
        whenNotPaused
        onlyRole(ADMIN_ROLE)
    {
        isArrowed[token] = allowed;
        emit TokenArrowed(token, allowed);
    }

    /// @notice Enforce the whitelist check for `sender` if a registry is configured.
    /// @param sender Address to check.
    /// @custom:reverts SENDER_NOT_WHITELISTED if a registry exists and the sender is not whitelisted
    function _enforceWL(address sender) internal view {
        if (address(whitelist) == address(0)) return;         // registry not set ⟹ no checks
        require(whitelist.isWhitelisted(sender), "SENDER_NOT_WHITELISTED");
    }

    // Whitelist admin

    /// @notice Set or clear the whitelist registry.
    /// @param registry Whitelist contract address, or zero to disable checks.
    /// @dev Only MINTER_ROLE may call.
    function setWhitelist(address registry) external whenNotPaused onlyRole(MINTER_ROLE) {
        whitelist = IWhitelist(registry);
    }

    // Internal modifiers

    /// @notice Accrue rewards into `accRewardPerShare` up to now, bounded by `finishAt`.
    /// @dev Updates `lastUpdate` to `min(now, finishAt)` and accrues only when shares exist and time has advanced.
    modifier updatePool() {
        uint256 end = block.timestamp < finishAt ? block.timestamp : finishAt;
        if (end > lastUpdate && totalShares > 0) {
            uint256 reward = (end - lastUpdate) * rewardRate;
            accRewardPerShare += (reward * 1e18) / totalShares;
        }
        lastUpdate = end;
        _;
    }

    /// @notice Gate functions to only whitelisted callers when a registry is configured.
    modifier onlyWhitelisted() {
        require(address(whitelist) == address(0) || whitelist.isWhitelisted(_msgSender()), "addr not whitelisted");
        _;
    }

    // Private helpers

    /// @notice Compute the pending unrounded reward for a position at the current accumulator.
    /// @param p Position snapshot.
    /// @return uint256 Raw pending reward.
    function _pending(Position memory p) private view returns (uint256) {
        return (p.shares * accRewardPerShare) / 1e18 - p.rewardDebt;
    }

    /// @notice Compute available reward liquidity as on-chain balance minus `reservedReward`.
    function _availableLiquidity() private view returns (uint256) {
        return rewardToken.balanceOf(address(this)) - reservedReward;
    }

    /// @notice Core position update for stake or unstake plus any pending reward payout.
    /// @param token Asset address.
    /// @param id Token id, where `0` is used for ERC20 positions.
    /// @param amount Share delta to add or remove.
    /// @param add True for stake, false for unstake.
    /// @return pending Amount paid out after rounding and reserve capping.
    /// @dev Emits `RewardClaimed` when a payout occurs and updates `rewardDebt` to the new checkpoint.
    /// @custom:reverts insufficient if the unstake amount exceeds the user's shares
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

    // ERC20 stake and unstake

    /// @notice Stake ERC20 tokens.
    /// @param token ERC20 to stake.
    /// @param amount Amount to stake.
    /// @dev Enforces cooldown and optional whitelist checks, applies any deposit fee, and emits `Staked`.
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

    /// @notice Unstake previously staked ERC20 tokens.
    /// @param token ERC20 address.
    /// @param amount Amount to unstake.
    /// @dev If unstaking the reward token itself, ensures on-chain liquidity is sufficient before transfer.
    /// @custom:reverts liquidity shortfall when unstaking rewardToken beyond available liquidity
    function unstakeERC20(address token, uint256 amount) external nonReentrant updatePool {
        if (token == address(rewardToken)) {
            require(_availableLiquidity() >= amount, "liquidity shortfall");
        }
        
        _updatePosition(token, 0, amount, false);
        IERC20(token).safeTransfer(_msgSender(), amount);
        emit Unstaked(_msgSender(), token, 0, amount);
    }

    // ERC721 stake and unstake

    /// @notice Stake one ERC721 token.
    /// @param token ERC721 collection.
    /// @param tokenId Token id to stake.
    /// @dev Enforces cooldown and whitelist checks, then transfers the NFT into the pool.
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

    /// @notice Unstake one ERC721 token.
    /// @param token ERC721 collection.
    /// @param tokenId Token id to unstake.
    function unstakeERC721(address token, uint256 tokenId) external nonReentrant updatePool {
        _updatePosition(token, tokenId, 1, false);
        IERC721(token).safeTransferFrom(address(this), _msgSender(), tokenId);
        emit Unstaked(_msgSender(), token, tokenId, 1);
    }

    // ERC1155 stake and unstake

    /// @notice Stake ERC1155 tokens.
    /// @param token ERC1155 collection.
    /// @param id Token id to stake.
    /// @param amount Units to stake.
    /// @dev Enforces cooldown and whitelist checks, applies any fee in units, and emits `Staked`.
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

    /// @notice Unstake ERC1155 tokens.
    /// @param token ERC1155 collection.
    /// @param id Token id to unstake.
    /// @param amount Units to unstake.
    /// @dev If unstaking the reward token itself, checks available liquidity before transfer.
    function unstakeERC1155(address token, uint256 id, uint256 amount) external nonReentrant updatePool {
        if (token == address(rewardToken)) {
            require(_availableLiquidity() >= amount, "liquidity shortfall");
        }
        _updatePosition(token, id, amount, false);
        IERC1155(token).safeTransferFrom(address(this), _msgSender(), id, amount, "");
        emit Unstaked(_msgSender(), token, id, amount);
    }

    /// @notice Round down `amt` to the configured `rewardPrecision`.
    /// @param amt Raw amount in 1e18 precision.
    /// @return uint256 Rounded amount.
    function _round(uint256 amt) internal view returns (uint256) {
        uint256 factor = 10 ** (18 - rewardPrecision);
        return (amt / factor) * factor;
    }

    // Claim reward

    /// @notice Claim accrued rewards for a specific `(token, id)` position.
    /// @param token Asset address.
    /// @param id Token id, or `0` for ERC20 positions.
    /// @dev Pays the rounded pending reward, updates `reservedReward`, and refreshes `rewardDebt`.
    /// @custom:reverts none if no pending reward remains after rounding
    function claim(address token, uint256 id) external onlyWhitelisted nonReentrant updatePool {
        Position storage pos = _positions[token][id][_msgSender()];
        uint256 pending = _round(_pending(pos));
        require(pending > 0, "none");
        reservedReward -= pending;
        pos.rewardDebt = (pos.shares * accRewardPerShare) / 1e18;
        rewardToken.safeTransfer(_msgSender(), pending);
        emit RewardClaimed(_msgSender(), pending);
    }

    // Scheduled actions API

    /// @notice Schedule a call to `target` with `value` and `data`.
    /// @param target Destination contract.
    /// @param value ETH value to send with the call.
    /// @param data Calldata, which must include a selector.
    /// @param delay Delay in seconds before first execution.
    /// @param recurring Whether the action should reschedule itself on success.
    /// @param interval Recurrence interval, required for recurring actions.
    /// @return id Newly assigned action id.
    /// @dev Only ADMIN_ROLE may schedule actions.
    /// @custom:reverts target=0 if target is zero
    /// @custom:reverts no selector if `data.length < 4`
    /// @custom:reverts bad interval if `recurring == true` and `interval == 0`
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

    /// @notice Execute a scheduled action when it is due.
    /// @param id Action id to execute.
    /// @dev Restricts targets to the reward token or arrowlisted assets and adjusts `reservedReward` around the call.
    /// @custom:reverts id if the id is out of range
    /// @custom:reverts time< if executed too early
    /// @custom:reverts done if already executed
    /// @custom:reverts target not whitelisted if the destination is neither the reward token nor an arrowlisted token
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

    // View helpers

    /// @notice Compute the raw unrounded pending reward for a user position at the current time.
    /// @param token Asset address.
    /// @param id Token id, or `0` for ERC20 positions.
    /// @param user User address.
    /// @return uint256 Unrounded pending reward.
    /// @dev Recomputes a hypothetical accumulator reflecting accrual to `min(now, finishAt)`.
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

    /// @notice Compute the rounded pending reward for a user position.
    /// @param token Asset address.
    /// @param id Token id, or `0` for ERC20 positions.
    /// @param user User address.
    /// @return uint256 Rounded pending reward according to `rewardPrecision`.
    function pendingReward(address token, uint256 id, address user)
        external
        view
        returns (uint256)
    {
        uint256 raw = pendingRawReward(token, id, user);
        return _round(raw);
    }

    /// @notice Read a stored user position.
    /// @param token Asset address.
    /// @param id Token id, or `0` for ERC20 positions.
    /// @param user User address.
    /// @return Position Stored position struct.
    function position(address token, uint256 id, address user) external view returns (Position memory) {
        return _positions[token][id][user];
    }

    /// @notice Return the number of scheduled actions.
    function actionsLength() external view returns (uint256) { return _actions.length; }

    // ERC721 / ERC1155 receiver hooks

    /// @notice ERC721 safe transfer receiver hook.
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /// @notice ERC1155 single transfer receiver hook.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    /// @notice ERC1155 batch transfer receiver hook.
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    // Pause and upgrade plumbing

    /// @notice Pause state-changing entrypoints; only PAUSER_ROLE.
    function pause()   external onlyRole(PAUSER_ROLE) { _pause();   }

    /// @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // meta-tx ---------------------------------------------------------------

    /// @dev ERC-2771 meta-tx sender override.
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /// @dev ERC-2771 meta-tx data override.
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /// @notice Return ERC165 support for AccessControl plus the receiver hooks.
    /// @param id Interface id.
    /// @return bool Whether supported.
    function supportsInterface(bytes4 id) public view override(AccessControlEnumerableUpgradeable, IERC165) returns (bool) {
        return id == type(IERC1155Receiver).interfaceId ||
               id == type(IERC721Receiver).interfaceId ||
               super.supportsInterface(id);
    }

    /// @notice Authorize a UUPS upgrade; only ADMIN_ROLE.
    /// @param newImpl Proposed implementation address.
    function _authorizeUpgrade(address newImpl) internal override onlyRole(ADMIN_ROLE) {}

    /// @dev Storage gap reserved for future upgrades.
    uint256[48] private __gap;
}

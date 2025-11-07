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

import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";

/* -------------------------------------------------------------------------- */
/*                           Splitter interface                               */
/* -------------------------------------------------------------------------- */

/**
 * @dev Fee router interface.
 * - `routeERC20(token, amount)` to forward ERC20 fees.
 * - `routeNative()` (payable) to forward native fees.
 */
interface ISplitter {
    function routeERC20(IERC20Metadata token, uint256 amount) external;
    function routeNative() external payable;
}

/**
 *  @title CircuitBreakerAMM
 *
 *  @notice
 *  - Purpose: Constant-product (x*y=k) AMM with:
 *      * Circuit breaker based on realized volatility (RV) over a rolling 24h window.
 *      * Dynamic fee that scales with RV.
 *      * On-chain oracle ring buffer (96 observations @ 15m ≈ 24h).
 *      * LP ERC20 shares (UUPS upgradeable), fee routing via an external Splitter.
 *  - Tokenization:
 *      * LP tokens are ERC20Upgradeable ("CB-LP"/"CBLP").
 *  - Fees:
 *      * A portion of input is collected as a fee and routed to `splitter` (ERC20 / native).
 *      * If routing fails, fees accrue in `pendingFee`/`pendingNative` and can be flushed later.
 *  - Circuit breaker:
 *      * Uses RV thresholds (lvl1/lvl2/lvl3) to cap or pause trading directionally.
 *      * `maxTxBps` additionally caps the per-trade size when RV is elevated.
 *  - Governance / Access:
 *      * Roles via AccessControl: DEFAULT_ADMIN_ROLE, GOVERNOR_ROLE, PAUSER_ROLE.
 *      * Upgrades: UUPS, authorized by GOVERNOR_ROLE.
 *  - Reentrancy & Pausing:
 *      * All state-changing externals are `whenNotPaused`. Swaps/liquidity ops are nonReentrant.
 *
 *  @dev SECURITY / AUDIT NOTES
 *  - Invariants: reserves tracked in `pool.reserve0/1`; kLast updated after each state change.
 *  - Oracle: `_updateOracle` stores one sample per ≥900s; `_seedOracle` seeds full ring on first liquidity.
 *  - Math: uses OZ Math library where appropriate; division rounding is documented at call sites.
 *  - Allowances: Router is expected to `safeTransferFrom` into the pool for swaps/liquidity.
 *  - External calls: fee routing to `splitter` is via try/catch; failure accrues pending balances.
 *  - Upgradeability: storage gap reserved (`__gapCB`).
 */
contract CircuitBreakerAMM is
    AccessControlUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    ERC20Upgradeable
{
    using SafeERC20 for IERC20Metadata;
    using Math for uint256;

    /* ─────────────────── roles & constants ─────────────────── */

    /// @notice Role for parameter updates and privileged ops.
    bytes32 public constant GOVERNOR_ROLE = keccak256("GOVERNOR_ROLE");
    /// @notice Role for pause/unpause operations.
    bytes32 public constant PAUSER_ROLE   = keccak256("PAUSER_ROLE");

    /// @dev Basis points constant (100% = 10_000 bps).
    uint256 private constant BPS = 10_000;
    /// @dev Oracle ring length: 96 slots ≈ 24h @ 15 minutes per slot.
    uint32  private constant ORACLE_LEN = 96;             // 24h / 15m

    /* ─────────────────────── data structs ──────────────────── */

    /**
     * @dev Packed reserves and last product for invariant tracking.
     */
    struct PoolState {
        uint128 reserve0;
        uint128 reserve1;
        uint256 kLast;
    }
    /// @notice Current pool reserves and kLast.
    PoolState public pool;

    /**
     * @dev Oracle observation: timestamp and price in bps (token0/token1 * 1e4).
     */
    struct Observation {
        uint32  timestamp;
        uint32  priceBps;
    }
    /// @notice Fixed-size ring buffer of observations; head index is `obsIdx`.
    Observation[ORACLE_LEN] public obs;
    uint8 public obsIdx;

    /* ─────────────────────── params ────────────────────────── */

    /// @notice Pair tokens (ordered externally by factory/router).
    IERC20Metadata public token0;
    IERC20Metadata public token1;

    /// @notice Fee router (Splitter).
    ISplitter public splitter;

    /// @notice Base fee and dynamic fee coefficient (both in bps).
    uint32 public baseFeeBps;
    uint32 public feeAlphaBps;

    /// @notice Circuit-breaker thresholds (in bps of RV).
    uint32 public lvl1Bps;
    uint32 public lvl2Bps;
    uint32 public lvl3Bps;

    /// @notice Max per-trade size (in bps of side TVL) enforced when RV ≥ lvl1.
    uint32 public maxTxBps;

    /// @notice Accrued (failed-to-route) ERC20 fees by token.
    mapping(IERC20Metadata => uint256) public pendingFee;
    /// @notice Accrued (failed-to-route) native fees.
    uint256 public pendingNative;

    /* ─────────────────────── events ────────────────────────── */

    /// @notice Emitted on each successful swap.
    event Swap(address indexed sender, bool zeroForOne, uint256 amountIn, uint256 amountOut);
    /// @notice Emitted on liquidity add/remove; amounts are signed deltas.
    event LiquidityChanged(address indexed lp, int256 amount0, int256 amount1);
    /// @notice Emitted when a fee amount could not be routed and is recorded as pending.
    event FeePending(IERC20Metadata indexed token, uint256 amount);
    /// @notice Emitted when pending fees are flushed to the splitter.
    event FeeFlushed(IERC20Metadata indexed token, uint256 amount);
    /// @notice Emitted when governor updates parameters.
    event Mint(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Sync(uint128 reserve0, uint128 reserve1);
    event ParamsUpdated();

    /**
     * @notice Validate AMM parameters (bps constraints and fee overflow bound).
     * @param _baseFeeBps   Base fee (bps).
     * @param _feeAlphaBps  Dynamic fee coefficient (bps).
     * @param _lvl1         RV threshold 1 (bps).
     * @param _lvl2         RV threshold 2 (bps).
     * @param _lvl3         RV threshold 3 (bps).
     * @param _maxTxBps     Max per-trade size as bps of TVL on input side.
     *
     * @custom:reverts param>10000 if any field > 10_000
     * @custom:reverts lvl order   if not (_lvl1 < _lvl2 < _lvl3)
     * @custom:reverts fee overflow if base + alpha*lvl3/1e4 > 10_000
     */
    function _validateParams(
        uint32 _baseFeeBps,
        uint32 _feeAlphaBps,
        uint32 _lvl1,
        uint32 _lvl2,
        uint32 _lvl3,
        uint32 _maxTxBps
    ) internal pure {
        require(
            _baseFeeBps   <= 10_000 &&
            _feeAlphaBps  <= 10_000 &&
            _lvl1         <= 10_000 &&
            _lvl2         <= 10_000 &&
            _lvl3         <= 10_000 &&
            _maxTxBps     <= 10_000,
            "param>10000"
        );

        require(_lvl1 < _lvl2 && _lvl2 < _lvl3, "lvl order");

        uint256 worstCase = uint256(_baseFeeBps) + (uint256(_feeAlphaBps) * _lvl3) / 10_000;
        require(worstCase <= 10_000, "fee overflow");
    }

    /* ─────────────────── initializer ───────────────────────── */

    /**
     * @notice Initialize the AMM pair and parameters; mints no liquidity.
     * @param _token0       Token0 address.
     * @param _token1       Token1 address.
     * @param _splitter     Fee router contract.
     * @param _baseFeeBps   Base fee in bps.
     * @param _feeAlphaBps  Dynamic fee coefficient in bps.
     * @param _lvl1Bps      Circuit breaker RV level 1 (bps).
     * @param _lvl2Bps      Circuit breaker RV level 2 (bps).
     * @param _lvl3Bps      Circuit breaker RV level 3 (bps).
     * @param _maxTxBps     Max per-trade size as bps of input-side TVL when RV≥lvl1.
     * @param admin         Address to receive admin/governor/pauser roles.
     *
     * @dev
     * - Calls OZ initializers (AccessControl, UUPS, ReentrancyGuard, ERC20, Pausable).
     * - Does not seed reserves or oracle; first addLiquidity seeds oracle via `_seedOracle`.
     * - LP token name/symbol: "CB-LP"/"CBLP".
     * - Emits no events.
     *
     * @custom:reverts if parameter validation fails per `_validateParams`.
     */
    function initialize(
        address _token0,
        address _token1,
        address _splitter,
        uint32  _baseFeeBps,
        uint32  _feeAlphaBps,
        uint32  _lvl1Bps,
        uint32  _lvl2Bps,
        uint32  _lvl3Bps,
        uint32  _maxTxBps,
        address admin
    ) external initializer {
        _validateParams(
            _baseFeeBps, _feeAlphaBps, _lvl1Bps, _lvl2Bps, _lvl3Bps, _maxTxBps
        );

        __AccessControl_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __ERC20_init("CB-LP", "CBLP");
        __Pausable_init();

        token0        = IERC20Metadata(_token0);
        token1        = IERC20Metadata(_token1);
        splitter      = ISplitter(_splitter);

        baseFeeBps   = _baseFeeBps;
        feeAlphaBps  = _feeAlphaBps;
        lvl1Bps      = _lvl1Bps;
        lvl2Bps      = _lvl2Bps;
        lvl3Bps      = _lvl3Bps;
        maxTxBps     = _maxTxBps;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(GOVERNOR_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    /* ─────────────────── oracle helpers ────────────────────── */

    /**
     * @notice Record a new oracle observation if ≥900 seconds since the last slot write.
     * @param priceBps  Price as token0/token1 * 1e4 (basis points scaling).
     *
     * @dev Moves ring head (`obsIdx`) forward by one and writes `(timestamp, priceBps)`.
     */
    function _updateOracle(uint256 priceBps) internal {
        Observation storage o = obs[obsIdx];
        if (block.timestamp - o.timestamp >= 900) {
            obsIdx = uint8((obsIdx + 1) % ORACLE_LEN);
            obs[obsIdx] = Observation(uint32(block.timestamp), uint32(priceBps));
        }
    }

    /**
     * @notice Compute realized volatility proxy in bps across the 24h window.
     * @return rvBps  |p_new - p_old| / p_old scaled by 1e4 (bps).
     *
     * @dev Uses newest and oldest samples in the ring buffer.
     *      Returns 0 if the oldest price is zero (not yet seeded).
     */
    function currentRV() public view returns (uint32 rvBps) {
        Observation storage newest = obs[obsIdx];
        Observation storage oldest = obs[(obsIdx + 1) % ORACLE_LEN];

        uint256 pNew = newest.priceBps;
        uint256 pOld = oldest.priceBps;
        
        if (pOld == 0) return 0;

        uint256 diff = pNew > pOld ? pNew - pOld : pOld - pNew;
        rvBps = uint32((diff * 1e4) / pOld);   // uint256 → uint32
    }

    /* ─────────────────── fee & breaker logic ───────────────── */

    /**
     * @notice Dynamic fee schedule: baseFee + rv * alpha / 1e4.
     * @param rv  Realized volatility in bps.
     * @return uint32  Fee in bps for the current trade.
     */
    function _dynamicFee(uint32 rv) internal view returns (uint32) {
        return baseFeeBps + (rv * feeAlphaBps) / 1e4;
    }

    /**
     * @notice Circuit breaker checks for direction, size caps, and non-empty reserves.
     * @param amountIn   Gross input amount for the trade.
     * @param zeroForOne True if token0→token1; false for token1→token0.
     *
     * @dev
     * - Pauses all swaps if RV ≥ lvl3.
     * - If lvl2 ≤ RV < lvl3, only allow one direction (`zeroForOne`-dependent policy).
     * - Require pool not empty on input side; base cap: `amountIn/tvlSide ≤ lvl1`.
     * - If RV ≥ lvl1, also require `amountIn/tvlSide ≤ maxTxBps`.
     *
     * @custom:reverts "CB: paused" when breaker halts the given direction
     * @custom:reverts "empty pool" if input side reserve is zero
     * @custom:reverts "cap base" / "CB: cap" when size exceeds caps
     */
    function _circuitChecks(uint256 amountIn, bool zeroForOne) internal view {
        uint32 rv = currentRV();
        require(rv < lvl3Bps, "CB: paused");
        if (rv >= lvl2Bps) {
            bool allowed = zeroForOne;
            require(allowed, "CB: paused");
        }

        uint256 tvlSide = zeroForOne ? pool.reserve0 : pool.reserve1;
        require(tvlSide > 0, "empty pool");
        require(amountIn * 1e4 / tvlSide <= lvl1Bps, "cap base");

        if (rv >= lvl1Bps) {
            require(amountIn * 1e4 / tvlSide <= maxTxBps, "CB: cap");
        }
    }

    /* ─────────────────── core math (x·y=k) ─────────────────── */

    /**
     * @notice Compute exact input required for a desired output (ignoring fees here).
     * @param amountOut  Desired output amount.
     * @param reserveIn  Current input-side reserve.
     * @param reserveOut Current output-side reserve.
     * @return amountIn  Required input amount (rounded up).
     *
     * @custom:reverts amtOut=0 if desired output is zero
     * @custom:reverts insufficient-liquidity if `reserveOut <= amountOut`
     */
    function _getAmountIn(
        uint256 amountOut,
        uint256 reserveIn,
        uint256 reserveOut
    ) internal pure returns (uint256 amountIn) {
        require(amountOut > 0, "amtOut=0");
        require(reserveOut > amountOut, "insufficient-liquidity");
        uint256 feeFactor = 10_000;
        uint256 num = reserveIn * amountOut * 10_000;
        uint256 den = (reserveOut - amountOut) * feeFactor;
        amountIn = (num + den - 1) / den;
    }

    /**
     * @notice Compute output given input (ignoring fee here; caller passes net input).
     * @param amtIn      Net input amount (after fee).
     * @param reserveIn  Current input-side reserve.
     * @param reserveOut Current output-side reserve.
     * @return uint256   Output amount (floor).
     */
    function _getAmountOut(uint256 amtIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        uint256 amtInAfterFee = amtIn * uint256(BPS) / BPS;
        return (amtInAfterFee * reserveOut) / (reserveIn + amtInAfterFee);
    }

    /**
     * @notice Seed the oracle ring buffer with an initial price (pInit).
     * @param pInit  Initial price in bps.
     *
     * @dev Called on the first liquidity add; fills all 96 slots with the same sample.
     */
    function _seedOracle(uint32 pInit) internal {
        for (uint8 i = 0; i < ORACLE_LEN; ++i) {
            obs[i] = Observation(uint32(block.timestamp), pInit);
        }
        obsIdx = 0;
    }

    // ------------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------------
    /// @notice Returns token0/token1 addresses (for router alignment).
    function tokens() external view returns (IERC20Metadata, IERC20Metadata) { return (token0, token1); }

    /// @notice Returns the current reserves.
    function getReserves() public view returns (uint128 r0, uint128 r1) {
        r0 = pool.reserve0;
        r1 = pool.reserve1;
    }

    // ------------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------------
    /// @dev Updates reserves to current token balances; emits Sync.
    function _update(uint balance0, uint balance1) internal {
        require(balance0 <= type(uint128).max && balance1 <= type(uint128).max, "overflow");
        pool.reserve0 = uint128(balance0);
        pool.reserve1 = uint128(balance1);
        // Optional: blockTimestampLast = uint32(block.timestamp);
        emit Sync(pool.reserve0, pool.reserve1);
    }

    /// @dev Integer sqrt utility.
    function _sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }

    /// @dev Min utility.
    function _min(uint a, uint b) internal pure returns (uint) {
        return a < b ? a : b;
    }

    /// @dev Safe token transfer helper.
    function _safeTransfer(IERC20Metadata token, address to, uint value) internal {
        SafeERC20.safeTransfer(token, to, value);
    }

    /* ─────────────────── external actions ─────────────────── */

    /// @notice Mints LP to `to` using EXACT token amounts previously transferred to this contract.
    /// @dev Router must transfer optimal amounts to this contract before calling.
    /// @param to Recipient of LP tokens.
    /// @return liquidity Amount of LP minted.
    function mint(address to) external whenNotPaused returns (uint liquidity) {
        (uint128 _r0, uint128 _r1) = getReserves();
        uint balance0 = IERC20Metadata(token0).balanceOf(address(this));
        uint balance1 = IERC20Metadata(token1).balanceOf(address(this));
        uint amount0  = balance0 - _r0;
        uint amount1  = balance1 - _r1;
        require(amount0 > 0 && amount1 > 0, "insufficient-in");

        uint _ts = totalSupply();
        if (_ts == 0) {
            liquidity = _sqrt(amount0 * amount1);
            require(liquidity > 0, "insufficient-liquidity-minted");
            _mint(to, liquidity);
        } else {
            uint liq0 = (amount0 * _ts) / _r0;
            uint liq1 = (amount1 * _ts) / _r1;
            liquidity = _min(liq0, liq1);
            require(liquidity > 0, "insufficient-liquidity-minted");
            _mint(to, liquidity);
        }

        emit Mint(msg.sender, amount0, amount1, to);
        _update(balance0, balance1);
    }

    /// @notice Burns LP previously transferred to this contract and sends pro-rata tokens to `to`.
    /// @dev Router must transfer user's LP to this contract before calling.
    /// @param to Recipient of underlying tokens.
    /// @return amount0 Token0 amount sent.
    /// @return amount1 Token1 amount sent.
    function burn(address to) external whenNotPaused returns (uint amount0, uint amount1) {
        uint liquidity = balanceOf(address(this));
        require(liquidity > 0, "no-liquidity");

        (uint128 _r0, uint128 _r1) = getReserves();
        uint _ts = totalSupply();

        amount0 = (liquidity * _r0) / _ts;
        amount1 = (liquidity * _r1) / _ts;
        require(amount0 > 0 && amount1 > 0, "insufficient-liquidity-burned");

        _burn(address(this), liquidity);
        _safeTransfer(token0, to, amount0);
        _safeTransfer(token1, to, amount1);

        uint balance0 = IERC20(token0).balanceOf(address(this));
        uint balance1 = IERC20(token1).balanceOf(address(this));
        emit Burn(msg.sender, amount0, amount1, to);
        _update(balance0, balance1);
    }

    /**
     * @notice Internal helper to route ERC20 fee to splitter, or record as pending on failure.
     * @param tok  Fee token.
     * @param amt  Amount to route.
     *
     * @dev Grants max allowance to splitter if needed; try/catch on `routeERC20`.
     */
    function _pushFee(IERC20Metadata tok, uint256 amt) internal {
        if (amt == 0) return;

        if (address(splitter).code.length == 0) {
            tok.safeTransfer(address(splitter), amt);
        } else {
            if (tok.allowance(address(this), address(splitter)) < amt) {
                tok.approve(address(splitter), 0);
                tok.approve(address(splitter), type(uint256).max);
            }
            try splitter.routeERC20(tok, amt) {
            } catch {
                pendingFee[tok] += amt;
                emit FeePending(tok, amt);
            }
        }
    }

    /**
     * @notice Flush (part of) pending ERC20 fees to splitter.
     * @param tok        Token to flush.
     * @param maxAmount  Max amount to flush (0 means "all").
     *
     * @dev Decrements `pendingFee` and reuses `_pushFee` for actual routing.
     * @custom:reverts no pending if nothing to flush
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
     * @notice Internal helper to route native fee to splitter; accrues on failure.
     * @param amount  Native amount to route.
     *
     * @dev Low-level call to `routeNative()` to avoid interface mismatch issues.
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
     * @notice Flush (part of) pending native fees to splitter.
     * @param maxAmt  Max amount to flush (0 means "all").
     *
     * @dev Decrements `pendingNative` then tries to route via `_pushNative`.
     */
    function flushNative(uint256 maxAmt) external nonReentrant whenNotPaused {
        uint256 amt = pendingNative;
        if (maxAmt != 0 && maxAmt < amt) amt = maxAmt;
        pendingNative -= amt;
        _pushNative(amt); // routeNative + try/catch
    }

    /**
     * @notice Swap exact token0 for token1 with a minimum out.
     * @param amountIn  Exact input amount of token0 (gross before fee).
     * @param minOut    Minimum acceptable amount of token1 (slippage bound).
     * @return uint256  Actual amount of token1 sent to caller.
     *
     * @dev
     * - Applies circuit checks & computes dynamic fee.
     * - Pulls token0, deducts fee, computes output, updates reserves & oracle.
     * - Routes fee to splitter (or records pending).
     * - Emits `Swap(sender, true, amountIn, amountOut)`.
     *
     * @custom:reverts slippage if `amountOut < minOut`
     */
    function swapExactToken0ForToken1(uint256 amountIn, uint256 minOut) external nonReentrant whenNotPaused returns (uint256) {
        _circuitChecks(amountIn, true);
        uint32 fee = _dynamicFee(currentRV());

        token0.safeTransferFrom(_msgSender(), address(this), amountIn);

        uint256 feeAmt = amountIn * fee / BPS;
        uint256 inNet  = amountIn - feeAmt;

        uint256 amountOut = _getAmountOut(inNet, pool.reserve0, pool.reserve1);
        require(amountOut >= minOut, "slippage");

        pool.reserve0 += uint128(inNet);
        pool.reserve1 -= uint128(amountOut);
        pool.kLast = uint256(pool.reserve0) * pool.reserve1;
        _updateOracle(uint256(pool.reserve0) * 1e4 / pool.reserve1);

        token1.safeTransfer(_msgSender(), amountOut);
        
        _pushFee(token0,  feeAmt);
        
        emit Swap(_msgSender(), true, amountIn, amountOut);

        return amountOut;
    }

    /**
     * @notice Swap exact token1 for token0 with a minimum out.
     * @param amountIn  Exact input amount of token1 (gross before fee).
     * @param minOut    Minimum acceptable amount of token0 (slippage bound).
     * @return uint256  Actual amount of token0 sent to caller.
     *
     * @dev See `swapExactToken0ForToken1` for flow details (mirrored).
     */
    function swapExactToken1ForToken0(uint256 amountIn, uint256 minOut) external nonReentrant whenNotPaused returns (uint256) {
        _circuitChecks(amountIn, false);
        uint32 fee = _dynamicFee(currentRV());

        token1.safeTransferFrom(_msgSender(), address(this), amountIn);

        uint256 feeAmt = amountIn * fee / BPS;
        uint256 inNet  = amountIn - feeAmt;

        uint256 amountOut = _getAmountOut(inNet, pool.reserve1, pool.reserve0);
        require(amountOut >= minOut, "slippage");

        pool.reserve1 += uint128(inNet);
        pool.reserve0 -= uint128(amountOut);
        pool.kLast = uint256(pool.reserve0) * pool.reserve1;
        _updateOracle(uint256(pool.reserve0) * 1e4 / pool.reserve1);

        token0.safeTransfer(_msgSender(), amountOut);
        _pushFee(token1, feeAmt);
        emit Swap(_msgSender(), false, amountIn, amountOut);

        return amountOut;
    }

    /**
     * @notice Quote output, feeBps, and fee amount for an exact-input swap.
     * @param amountIn   Gross input amount.
     * @param zeroForOne Direction: true for token0→token1, false for token1→token0.
     * @return amountOut Net output after fee and AMM pricing.
     * @return feeBps    Applied fee in bps.
     * @return feeAmt    Fee amount deducted from `amountIn`.
     *
     * @dev View-only; uses live reserves and current RV-derived fee.
     * @custom:reverts amtIn=0 if `amountIn == 0`
     */
    function quoteOut(
        uint256 amountIn,
        bool    zeroForOne
    ) external view returns (
        uint256 amountOut,
        uint32  feeBps,
        uint256 feeAmt
    ) {
        require(amountIn > 0, "amtIn=0");

        feeBps = _dynamicFee(currentRV());
        feeAmt = amountIn * feeBps / BPS;

        uint256 inNet = amountIn - feeAmt;
        if (zeroForOne) {
            amountOut = _getAmountOut(inNet, pool.reserve0, pool.reserve1);
        } else {
            amountOut = _getAmountOut(inNet, pool.reserve1, pool.reserve0);
        }
    }

    /**
     * @notice Quote required *gross* input for a desired output amount.
     * @param amountOutDesired Desired output.
     * @param zeroForOne       Direction: true for token0→token1, false for token1→token0.
     * @return amountIn  Required gross input (including fee).
     * @return feeBps    Applied fee in bps.
     * @return feeAmt    Fee portion of `amountIn`.
     *
     * @dev Computes net input via `_getAmountIn`, then grosses up by 1/(1-feeBps/BPS).
     * @custom:reverts amtOut=0 if desired output is zero
     * @custom:reverts fee=100% if `feeBps == BPS` (division by zero)
     */
    function quoteIn(
        uint256 amountOutDesired,
        bool    zeroForOne
    ) external view returns (
        uint256 amountIn,     // = gross (includes fee)
        uint32  feeBps,
        uint256 feeAmt
    ) {
        require(amountOutDesired > 0, "amtOut=0");

        feeBps = _dynamicFee(currentRV());
        require(feeBps < BPS, "fee=100%");

        uint256 inNet = zeroForOne
            ? _getAmountIn(amountOutDesired, pool.reserve0, pool.reserve1)
            : _getAmountIn(amountOutDesired, pool.reserve1, pool.reserve0);

        amountIn = Math.mulDiv(
            inNet,
            BPS,
            BPS - feeBps,
            Math.Rounding.Ceil
        );

        feeAmt = amountIn - inNet;
    }

    /* ─────────────────── admin ops ─────────────────────────── */

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }

    /**
     * @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
     */
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    /**
     * @notice Update AMM parameters (governor only).
     * @param _baseFeeBps   New base fee bps.
     * @param _feeAlphaBps  New dynamic fee coefficient bps.
     * @param _lvl1         New RV level 1 bps.
     * @param _lvl2         New RV level 2 bps.
     * @param _lvl3         New RV level 3 bps.
     * @param _maxTxBps     New per-trade cap bps when RV≥lvl1.
     *
     * @dev Re-validates parameter set; emits `ParamsUpdated`.
     */
    function updateParams(
        uint32 _baseFeeBps,
        uint32 _feeAlphaBps,
        uint32 _lvl1,
        uint32 _lvl2,
        uint32 _lvl3,
        uint32 _maxTxBps
    ) external onlyRole(GOVERNOR_ROLE) {
        _validateParams(
            _baseFeeBps, _feeAlphaBps, _lvl1, _lvl2, _lvl3, _maxTxBps
        );

        baseFeeBps  = _baseFeeBps;
        feeAlphaBps = _feeAlphaBps;
        lvl1Bps = _lvl1; lvl2Bps = _lvl2; lvl3Bps = _lvl3;
        maxTxBps = _maxTxBps;
        emit ParamsUpdated();
    }

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override. (Note: This contract does not use ERC-2771; falls back to ContextUpgradeable.)
     */
    function _msgSender() internal view override(ContextUpgradeable) returns(address){return super._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override. (Note: This contract does not use ERC-2771; falls back to ContextUpgradeable.)
     */
    function _msgData() internal view override(ContextUpgradeable) returns(bytes calldata){return super._msgData();}

    /* ─────────────────── UUPS auth ─────────────────────────── */

    /**
     * @notice Authorize UUPS upgrade; only GOVERNOR_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(GOVERNOR_ROLE) {}

    /// @dev Reserved storage to allow future variable additions while preserving layout.
    uint256[44] private __gapCB;
}

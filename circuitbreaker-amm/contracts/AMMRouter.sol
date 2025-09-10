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

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

import "./AMMFactory.sol";
import "./CircuitBreakerAMM.sol";

/**
 * @dev Minimal WNATIVE interface (ERC20 with deposit/withdraw).
 * - `deposit()` wraps ETH into WNATIVE; `withdraw(amount)` unwraps WNATIVE into ETH.
 */
interface IWNative is IERC20 {
    function deposit() external payable;
    function withdraw(uint256) external;
}

/**
 *  @title AMMRouter
 *
 *  @notice
 *  - Purpose: Routing helper for CircuitBreakerAMM pools created by AMMFactory.
 *             Supports multi-hop swaps (ERC20↔ERC20), ETH wrapping/unwrapping via WNATIVE,
 *             single-sided liquidity add for (token, WNATIVE), and quoting along a path.
 *  - Architecture:
 *      * Pools are discovered through AMMFactory (deterministic pair mapping).
 *      * For swaps, this router approves the pool once (infinite allowance) and the pool "pulls" tokens.
 *      * Multi-hop: executes sequential swaps, enforcing slippage only on the final output.
 *      * ETH integration: wraps to WNATIVE on entry, unwraps at the end when returning ETH.
 *  - Access: All functions are public/external; no owner/governance in the router.
 *  - Upgradeability / Meta-tx:
 *      * This contract is non-upgradeable and does not implement ERC-2771; therefore no `_authorizeUpgrade` or `_msgSender` overrides here.
 *  - Security / Audit Notes:
 *      * Trusts AMMFactory to return pools with compatible interfaces (CircuitBreakerAMM).
 *      * `_ensureAllowance` resets allowance to 0 then sets `type(uint256).max` to accommodate non-standard ERC20s that require zeroing.
 *      * Reentrancy: `addLiquidityETH` is `nonReentrant` due to handling ETH and external calls. Swaps intentionally omit `nonReentrant`
 *        since router holds no mutable state and `sendValue` is the last operation after state-free accounting.
 *      * Slippage: Only the final hop checks `amountOutMin`; intermediate hops can vary but the final bound protects the user.
 *      * ETH receive: restricted to WNATIVE contract to prevent accidental ETH transfers (forces use of router entrypoints).
 *
 *  Related:
 *  - AMMFactory: provides pool addresses via `getPool(token0, token1)`.
 *  - CircuitBreakerAMM: must expose `swapExactToken0ForToken1`, `swapExactToken1ForToken0`,
 *    `addLiquidity`, and `quoteOut`.
 */

contract AMMRouter is ReentrancyGuard {
    using SafeERC20 for IERC20;
    using Address for address payable;

    /// @notice Factory used to resolve pool addresses for token pairs.
    AMMFactory public immutable factory;

    /// @notice Wrapped native token (e.g., WETH/WAVAX/WBNB).
    IWNative   public immutable WNATIVE;

    /**
     * @notice Deploy the router.
     * @param _factory  Address of AMMFactory (must be non-zero).
     * @param _wnative  Address of WNATIVE token (must be non-zero).
     *
     * @custom:reverts zero if any address is zero
     */
    constructor(address _factory, address _wnative) {
        require(_factory != address(0) && _wnative != address(0), "zero");
        factory  = AMMFactory(_factory);
        WNATIVE  = IWNative(_wnative);
    }

    /* ------------------------------------------------------------------ */
    /*                       Internal helpers                             */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Find the pool for (a,b) using canonical ordering and indicate swap direction.
     * @param a  Input token address for this hop.
     * @param b  Output token address for this hop.
     * @return pool       The pool address registered for (token0, token1).
     * @return zeroForOne True if input is token0→token1, false if token1→token0.
     *
     * @dev Reverts if the pool does not exist in factory (pair not created).
     * @custom:reverts pool missing if no pool is registered
     */
    function _poolSorted(address a, address b)
        internal view
        returns (address pool, bool zeroForOne)
    {
        if (a < b) {
            pool = factory.getPool(a, b);
            zeroForOne = true;
        } else {
            pool = factory.getPool(b, a);
            zeroForOne = false;
        }
        require(pool != address(0), "pool missing");
    }

    /**
     * @notice Ensure `spender` has sufficient allowance of `token` from this router.
     * @param token    ERC20 token address to approve.
     * @param spender  Target spender contract (e.g., pool).
     * @param need     Minimum allowance required.
     *
     * @dev Pattern: set allowance to 0 then to max to support tokens that require zeroing.
     *      Grants infinite approval to minimize repeat approvals across multiple swaps.
     */
    function _ensureAllowance(address token, address spender, uint256 need) internal {
        uint256 cur = IERC20(token).allowance(address(this), spender);
        if (cur < need) {
            IERC20(token).approve(spender, 0);
            IERC20(token).approve(spender, type(uint256).max);
        }
    }

    /**
     * @notice Execute a single-hop swap on the resolved pool.
     * @param input     Input token for this hop.
     * @param output    Output token for this hop.
     * @param amountIn  Exact input amount to swap.
     * @return outAmt   Amount received from this hop.
     *
     * @dev
     * - Determines direction with `_poolSorted`.
     * - Approves the pool to pull `input` if needed.
     * - Calls the appropriate pool function with `minOut=0` (final slippage checked at the end of the path).
     */
    function _swap(
        address input,
        address output,
        uint256 amountIn
    ) internal returns (uint256 outAmt) {
        (address pool, bool zf1) = _poolSorted(input, output);

        // approve once
        _ensureAllowance(input, pool, amountIn);

        // call swap (pool will pull)
        if (zf1) {
            outAmt = CircuitBreakerAMM(pool).swapExactToken0ForToken1(amountIn, 0);
        } else {
            outAmt = CircuitBreakerAMM(pool).swapExactToken1ForToken0(amountIn, 0);
        }
    }

    /* ------------------------------------------------------------------ */
    /*                       Core swap functions                           */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Swap an exact `amountIn` of `path[0]` to `path[-1]` via multi-hop.
     * @param amountIn      Exact input amount of the first token.
     * @param amountOutMin  Minimum acceptable final output amount (slippage bound).
     * @param path          Swap path: length ≥ 2, contiguous token addresses.
     * @param to            Recipient of the final output tokens.
     * @param deadline      Unix timestamp after which the tx is invalid.
     * @return amountOut    Final output amount delivered to `to`.
     *
     * @dev
     * - Transfers `amountIn` from caller to the router.
     * - Iteratively swaps hop-by-hop using `_swap`.
     * - Enforces final slippage check against `amountOutMin`.
     * - Emits pool-specific events inside pools; the router itself does not emit swap events.
     *
     * @custom:reverts expired   if `block.timestamp > deadline`
     * @custom:reverts path len  if `path.length < 2`
     * @custom:reverts slippage  if final `amt < amountOutMin`
     */
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) public returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "expired");
        require(path.length >= 2, "path len");

        IERC20(path[0]).safeTransferFrom(msg.sender, address(this), amountIn);

        uint256 amt = amountIn;
        for (uint256 i; i < path.length - 1; ++i) {
            amt = _swap(path[i], path[i+1], amt);
        }

        require(amt >= amountOutMin, "slippage");
        IERC20(path[path.length - 1]).safeTransfer(to, amt);
        return amt;
    }

    /**
     * @notice Swap exact ETH (msg.value) for tokens along a path that starts with WNATIVE.
     * @param amountOutMin  Minimum acceptable final output amount.
     * @param path          Must start with `WNATIVE` and have length ≥ 2.
     * @param to            Recipient of final tokens.
     * @param deadline      Unix timestamp after which the tx is invalid.
     * @return amountOut    Final output amount delivered to `to`.
     *
     * @dev Wraps ETH into WNATIVE, then delegates to `swapExactTokensForTokens`.
     * @custom:reverts path invalid if `path.length < 2` or `path[0] != WNATIVE`
     */
    function swapExactETHForTokens(
        uint256 amountOutMin,
        address[] calldata path, // must start with WNATIVE
        address to,
        uint256 deadline
    ) external payable returns (uint256 amountOut) {
        require(path.length >= 2 && path[0] == address(WNATIVE), "path invalid");
        WNATIVE.deposit{value: msg.value}(); // wrap ETH
        amountOut = swapExactTokensForTokens(msg.value, amountOutMin, path, to, deadline);
    }

    /**
     * @notice Swap exact tokens for ETH along a path that ends with WNATIVE, then unwrap.
     * @param amountIn      Exact input amount of the first token.
     * @param amountOutMin  Minimum acceptable ETH out after unwrapping.
     * @param path          Must end with `WNATIVE` and have length ≥ 2.
     * @param to            Recipient of unwrapped ETH.
     * @param deadline      Unix timestamp after which the tx is invalid.
     * @return amountOut    Final ETH amount sent to `to`.
     *
     * @dev
     * - Performs token→WNATIVE path swap to the router.
     * - Unwraps all WNATIVE balance to ETH.
     * - Sends ETH to `to` using `Address.sendValue`.
     * @custom:reverts path invalid if last path token != WNATIVE
     * @custom:reverts slippage    if resulting WNATIVE (then ETH) < amountOutMin
     */
    function swapExactTokensForETH(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path, // must end with WNATIVE
        address to,
        uint256 deadline
    ) external returns (uint256 amountOut) {
        require(path[path.length - 1] == address(WNATIVE), "path invalid");
        swapExactTokensForTokens(amountIn, 0, path, address(this), deadline);
        uint256 wBal = WNATIVE.balanceOf(address(this));
        require(wBal >= amountOutMin, "slippage");
        WNATIVE.withdraw(wBal);
        payable(to).sendValue(wBal);
        return wBal;
    }

    /* ------------------------------------------------------------------ */
    /*                       Liquidity wrappers                            */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Add liquidity to a (token, WNATIVE) pool using exact sent ETH and `amountTokenDesired`.
     * @param token              ERC20 token paired with WNATIVE.
     * @param amountTokenDesired Desired token amount to add.
     * @param amountTokenMin     Minimum token amount acceptable (slippage guard).
     * @param amountETHMin       Minimum ETH amount acceptable (slippage guard).
     * @param to                 Recipient of the LP tokens.
     * @param deadline           Unix timestamp after which the tx is invalid.
     * @return liquidity         Amount of LP tokens minted and transferred to `to`.
     *
     * @dev
     * - Resolves pool for (token, WNATIVE); reverts if missing.
     * - Pulls `amountTokenDesired` from caller; wraps `msg.value` into WNATIVE.
     * - Approves pool for both token and WNATIVE if needed.
     * - Checks both token and ETH minimums before calling `addLiquidity`.
     * - Transfers LP tokens to `to`.
     *
     * @custom:reverts expired   if `block.timestamp > deadline`
     * @custom:reverts slippage  if `amountTokenDesired < amountTokenMin` or `msg.value < amountETHMin`
     */
    function addLiquidityETH(
        address token,
        uint256 amountTokenDesired,
        uint256 amountTokenMin,
        uint256 amountETHMin,
        address to,
        uint256 deadline
    ) external payable nonReentrant returns (uint256 liquidity)
    {
        require(block.timestamp <= deadline, "expired");

        (address pool, ) = _poolSorted(token, address(WNATIVE));

        IERC20(token).safeTransferFrom(msg.sender, address(this), amountTokenDesired);
        _ensureAllowance(token, pool, amountTokenDesired);

        WNATIVE.deposit{value: msg.value}();
        _ensureAllowance(address(WNATIVE), pool, msg.value);

        require(amountTokenDesired >= amountTokenMin && msg.value >= amountETHMin, "slippage");

        liquidity = CircuitBreakerAMM(pool).addLiquidity(
            amountTokenDesired,
            msg.value
        );

        IERC20(pool).safeTransfer(to, liquidity);
    }

    /**
     * @notice Quote the final output and total fee for an exact-input multi-hop swap (view).
     * @param amountIn  Exact input amount at the first hop.
     * @param path      Swap path: length ≥ 2.
     * @return amountOut Final output amount after all hops.
     * @return totalFee  Sum of per-hop fee amounts reported by pools.
     *
     * @dev Iteratively calls each pool's `quoteOut(amountIn, zeroForOne)` without state changes.
     * @custom:reverts path len if `path.length < 2`
     */
    function quoteExactTokensForTokens(
        uint256 amountIn,
        address[] calldata path
    ) external view returns (uint256 amountOut, uint256 totalFee) {
        require(path.length >= 2, "path len");

        amountOut = amountIn;
        for (uint i; i < path.length - 1; ++i) {
            (address pool, bool zf1) = _poolSorted(path[i], path[i+1]);

            (uint out, , uint feeAmt) =
                CircuitBreakerAMM(pool).quoteOut(amountOut, zf1);

            amountOut = out;
            totalFee += feeAmt;
        }
    }

    /* ------------------------------------------------------------------ */
    /*                       Fallback / Receive                            */
    /* ------------------------------------------------------------------ */

    /**
     * @notice Receive hook for unwrapping WNATIVE only.
     * @dev Reject all direct ETH transfers except from WNATIVE contract (WNATIVE.withdraw).
     * @custom:reverts direct eth disallowed if sender is not WNATIVE
     */
    receive() external payable {
        require(msg.sender == address(WNATIVE), "direct eth disallowed");
    }
}

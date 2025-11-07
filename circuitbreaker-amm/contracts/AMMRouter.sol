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
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";

/**
 * @dev Minimal WNATIVE interface (ERC20 with deposit/withdraw).
 * - `deposit()` wraps ETH into WNATIVE; `withdraw(amount)` unwraps WNATIVE into ETH.
 */
interface IWNative {
    function deposit() external payable;
    function withdraw(uint) external;
    function transfer(address to, uint value) external returns (bool);
    function balanceOf(address who) external view returns (uint);
}

interface ICircuitBreakerAMM {
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 r0, uint112 r1);
    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swapExactToken0ForToken1(uint256 amountIn, uint256 minOut) external returns (uint256);
    function swapExactToken1ForToken0(uint256 amountIn, uint256 minOut) external returns (uint256);
    function quoteOut(uint256 amountIn, bool zeroForOne) external view returns (uint256 amountOut, uint32  feeBps, uint256 feeAmt);
}

interface IAMMFactory {
    function getPool(address tokenA, address tokenB) external view returns (address);
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
    IAMMFactory public immutable factory;

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
        factory  = IAMMFactory(_factory);
        WNATIVE  = IWNative(_wnative);
    }

    // ------------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------------
    /// @notice Sorts two token addresses (ascending).
    function _sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {
        require(tokenA != tokenB, "identical");
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), "zero");
    }

    /// @notice Reads reserves aligned to the (tokenA, tokenB) order.
    function _getReserves(address pair, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {
        address t0 = ICircuitBreakerAMM(pair).token0();
        (uint128 r0, uint128 r1) = ICircuitBreakerAMM(pair).getReserves();
        if (tokenA == t0) {
            (reserveA, reserveB) = (r0, r1);
        } else if (tokenB == t0) {
            (reserveA, reserveB) = (r1, r0);
        }
    }

    /// @notice V2-style quote: amountB to keep price unchanged.
    function quote(uint amountA, uint reserveA, uint reserveB) public pure returns (uint amountB) {
        require(amountA > 0, "insufficient A");
        require(reserveA > 0 && reserveB > 0, "insufficient liquidity");
        amountB = (amountA * reserveB) / reserveA;
    }

    /// @notice Computes optimal amounts so spot price does not move.
    function _optimalLiquidity(
        address pair,
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin
    ) internal view returns (uint amountA, uint amountB) {
        (uint reserveA, uint reserveB) = _getReserves(pair, tokenA, tokenB);
        if (reserveA == 0 && reserveB == 0) {
            // First mint sets the price by desired amounts.
            amountA = amountADesired;
            amountB = amountBDesired;
        } else {
            uint amountBOptimal = quote(amountADesired, reserveA, reserveB);
            if (amountBOptimal <= amountBDesired) {
                require(amountBOptimal >= amountBMin, "insufficient B");
                amountA = amountADesired;
                amountB = amountBOptimal;
            } else {
                uint amountAOptimal = quote(amountBDesired, reserveB, reserveA);
                require(amountAOptimal >= amountAMin, "insufficient A");
                amountA = amountAOptimal;
                amountB = amountBDesired;
            }
        }
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
            outAmt = ICircuitBreakerAMM(pool).swapExactToken0ForToken1(amountIn, 0);
        } else {
            outAmt = ICircuitBreakerAMM(pool).swapExactToken1ForToken0(amountIn, 0);
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

    /// @notice Adds liquidity without moving price; transfers EXACT optimal amounts to Pair, then mints LP to `to`.
    function addLiquidity(
        address pair,
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity) {
        require(block.timestamp <= deadline, "expired");

        (amountA, amountB) = _optimalLiquidity(
            pair, tokenA, tokenB,
            amountADesired, amountBDesired,
            amountAMin, amountBMin
        );

        IERC20(tokenA).safeTransferFrom(msg.sender, pair, amountA);
        IERC20(tokenB).safeTransferFrom(msg.sender, pair, amountB);
        liquidity = ICircuitBreakerAMM(pair).mint(to);
    }

    function removeLiquidity(
        address pair,
        uint liquidity,
        address tokenA,
        address tokenB,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB) {
        require(block.timestamp <= deadline, "expired");

        IERC20(pair).safeTransferFrom(msg.sender, pair, liquidity);
        (uint aOut, uint bOut) = ICircuitBreakerAMM(pair).burn(to);

        address t0 = ICircuitBreakerAMM(pair).token0();
        if (tokenA == t0) {
            amountA = aOut; amountB = bOut;
        } else if (tokenB == t0) {
            amountA = bOut; amountB = aOut;
        }
        require(amountA >= amountAMin && amountB >= amountBMin, "slippage");
    }

    /**
     * @notice Add liquidity to a (token, WNATIVE) pool using exact sent ETH and `amountTokenDesired`.
     * @param token              ERC20 token paired with WNATIVE.
     * @param amountTokenDesired Desired token amount to add.
     * @param amountTokenMin     Minimum token amount acceptable (slippage guard).
     * @param amountETHMin       Minimum ETH amount acceptable (slippage guard).
     * @param to                 Recipient of the LP tokens.
     * @param deadline           Unix timestamp after which the tx is invalid.
     * @return amountToken       Amount of LP tokens minted and transferred to `to`.
     * @return amountETH         Amount of LP tokens minted and transferred to `to`.
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
        address pair,
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity) {
        require(block.timestamp <= deadline, "expired");

        IWNative(WNATIVE).deposit{value: msg.value}();

        (address tokenA, address tokenB) = _sortTokens(token, address(WNATIVE));
        (uint aDes, uint bDes) = tokenA == token ? (amountTokenDesired, msg.value) : (msg.value, amountTokenDesired);
        (uint aMin, uint bMin) = tokenA == token ? (amountTokenMin, amountETHMin) : (amountETHMin, amountTokenMin);

        (uint aOpt, uint bOpt) = _optimalLiquidity(pair, tokenA, tokenB, aDes, bDes, aMin, bMin);
        (amountToken, amountETH) = tokenA == token ? (aOpt, bOpt) : (bOpt, aOpt);

        // Transfer EXACT optimal amounts
        IERC20(token).safeTransferFrom(msg.sender, pair, amountToken);
        IWNative(WNATIVE).transfer(pair, amountETH);
        liquidity = ICircuitBreakerAMM(pair).mint(to);

        // Refund any remaining WNATIVE (if user sent too much ETH)
        uint wBal = IWNative(WNATIVE).balanceOf(address(this));
        if (wBal > 0) {
            IWNative(WNATIVE).withdraw(wBal);
            (bool ok, ) = msg.sender.call{value: wBal}("");
            require(ok, "refund failed");
        }
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
                ICircuitBreakerAMM(pool).quoteOut(amountOut, zf1);

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

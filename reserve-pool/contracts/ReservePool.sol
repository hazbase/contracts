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

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/// @dev Minimal Uniswap-V2 style router interface used for buy-backs.
interface IRouterLike {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/**
 * @title ReservePool
 *
 * @notice
 * - Purpose: Treasury sub-module to manage protocol reserves split into two buckets
 *   **per token**:
 *   1) **Liquidity** bucket — used to perform market buy-backs of `protocolToken`.
 *   2) **Compensation** bucket — used to compensate users in incident scenarios.
 *
 * - Features:
 *   * Role-gated funding, buy-back, and compensation flows.
 *   * Configurable buy-back cooldown per input token.
 *   * AMM-agnostic via minimal router interface (e.g., Uniswap V2-like).
 *   * ERC-2771 meta-transactions & UUPS upgradeable.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Allowances: buy-backs use `safeIncreaseAllowance` (no reset-to-zero) to the router.
 * - Cooldown: `triggerBuyBack` enforces a per-token cooldown to throttle spend.
 * - Accounting: internal balances use `uint128`, enforced by require checks on inputs.
 * - ETH handling: `address(0)` denotes native ETH; `receive()` credits the compensation bucket.
 * - Access control: roles—`ROYALTY_ROLE` (fund), `CIRCUIT_BREAKER_ROLE` (buy-back),
 *   `GUARDIAN_ROLE` (pay compensation / sweep), `PAUSER_ROLE` (pause), `ADMIN_ROLE` (upgrade).
 */
 
contract ReservePool is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    /*────────────────────────── Roles ──────────────────────────*/

    /// @notice Role allowed to trigger buy-backs during circuit-break events.
    bytes32 public constant CIRCUIT_BREAKER_ROLE = keccak256("CIRCUIT_BREAKER_ROLE");

    /*────────────────────────── Storage ────────────────────────*/

    /**
     * @dev Per-token reserve buckets.
     * @param liquidity    Usable balance for buy-backs (router swaps).
     * @param compensation Reserved balance for user compensation payouts.
     */
    struct Balances {
        uint128 liquidity;
        uint128 compensation;
    }

    /// @dev Token => Balances
    mapping(address => Balances) private _tokenBalances;

    /// @dev Last buy-back timestamp per input token (used for cooldown).
    mapping(address => uint256) public lastBuyBackAt;

    /// @notice Seconds between buy-backs per `tokenIn`.
    uint256 public buyBackCooldown;

    /// @notice AMM router used to perform buy-backs.
    IRouterLike public router;

    /// @notice Protocol token to be bought back (must be last element of swap path).
    address public protocolToken;

    /*────────────────────────── Events ─────────────────────────*/

    /// @notice Emitted when liquidity bucket is funded.
    event LiquidityFunded(address indexed token, uint256 amount);
    /// @notice Emitted when compensation bucket is funded.
    event CompensationFunded(address indexed token, uint256 amount);
    /// @notice Emitted after a successful buy-back swap.
    event BuyBackExecuted(address indexed tokenIn, uint256 amountIn, uint256 amountOut, uint256 newLiquidity);
    /// @notice Emitted after paying out compensation to an address.
    event CompensationPaid(address indexed token, address indexed to, uint256 amount);
    /// @notice Emitted when sweeping between buckets.
    event Sweep(address indexed token, uint256 amount, bool toCompensation);
    /// @notice Emitted when cooldown is updated.
    event BuyBackCooldownUpdated(uint256 newCooldown);

    /*────────────────────────── Initializer ────────────────────*/

    /**
     * @notice Initialize the reserve pool.
     * @param admin           Address to be granted admin/guardian/… roles via RolesCommon.
     * @param router_         AMM router used for buy-backs.
     * @param protocolToken_  Token to accumulate via buy-backs (must be path end).
     * @param forwarders      Trusted ERC-2771 forwarders for meta-transactions.
     *
     * @dev Sets default buy-back cooldown to 1 day.
     *
     * @custom:reverts router=0        if `router_` is zero
     * @custom:reverts protocolToken=0 if `protocolToken_` is zero
     */
    function initialize(
        address admin,
        address router_,
        address protocolToken_,
        address[] calldata forwarders
    ) external initializer {
        require(router_ != address(0), "router=0");
        require(protocolToken_ != address(0), "protocolToken=0");

        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);
        __Pausable_init();

        router = IRouterLike(router_);
        protocolToken = protocolToken_;
        buyBackCooldown = 1 days;
    }

    /*────────────────────────── Configuration ─────────────────*/

    /**
     * @notice Update the global buy-back cooldown.
     * @param newCooldown New cooldown in seconds (0 < newCooldown < 30 days).
     *
     * @dev Only GUARDIAN_ROLE. Emits `BuyBackCooldownUpdated`.
     *
     * @custom:reverts invalid cooldown if outside (0, 30 days)
     */
    function setBuyBackCooldown(uint256 newCooldown) external onlyRole(GUARDIAN_ROLE) {
        require(newCooldown > 0 && newCooldown < 30 days, "invalid cooldown");
        buyBackCooldown = newCooldown;
        emit BuyBackCooldownUpdated(newCooldown);
    }

    /*────────────────────────── Reserve Funding ───────────────*/

    /**
     * @notice Fund the **liquidity** bucket for `token` by `amount`.
     * @param token  ERC20 token address or address(0) for native ETH.
     * @param amount Amount to fund (wei for ETH; token units for ERC20).
     *
     * @dev Caller must have ROYALTY_ROLE (e.g., DAO/FeeTreasury).
     *      Uses `_receiveToken` to collect ERC20/ETH safely.
     *      Emits `LiquidityFunded`.
     */
    function fundLiquidity(address token, uint256 amount) external payable onlyRole(ROYALTY_ROLE) {
        _receiveToken(token, amount);
        _tokenBalances[token].liquidity += uint128(amount);
        emit LiquidityFunded(token, amount);
    }

    /**
     * @notice Fund the **compensation** bucket for `token` by `amount`.
     * @param token  ERC20 token address or address(0) for native ETH.
     * @param amount Amount to fund.
     *
     * @dev Caller must have ROYALTY_ROLE. Emits `CompensationFunded`.
     */
    function fundCompensation(address token, uint256 amount) external payable onlyRole(ROYALTY_ROLE) {
        _receiveToken(token, amount);
        _tokenBalances[token].compensation += uint128(amount);
        emit CompensationFunded(token, amount);
    }

    /*────────────────────────── Forced Buy-Back ───────────────*/

    /**
     * @notice Execute a buy-back swap from `tokenIn` to `protocolToken` via router.
     * @param tokenIn       Reserve token to spend (e.g., stablecoin or WETH).
     * @param amountIn      Amount taken from the **liquidity** bucket.
     * @param minAmountOut  Minimum `protocolToken` expected (slippage guard).
     * @param path          Router swap path (must start with `tokenIn` and end with `protocolToken`).
     * @return amountOut    Actual amount of `protocolToken` received.
     *
     * @dev
     * - Only `CIRCUIT_BREAKER_ROLE`.
     * - Enforces `buyBackCooldown` per `tokenIn`.
     * - Deducts from liquidity bucket before swap; increases allowance if needed.
     * - Sets a 15-minute router deadline (now + 900).
     * - Emits `BuyBackExecuted` and updates `lastBuyBackAt[tokenIn]`.
     *
     * @custom:reverts COOLDOWN                 if last swap was too recent
     * @custom:reverts path length              if `path.length < 2`
     * @custom:reverts path[0] != tokenIn       if path start mismatch
     * @custom:reverts path end != protocolToken if path end mismatch
     * @custom:reverts insufficient reserve     if `amountIn > liquidity`
     */
    function triggerBuyBack(
        address tokenIn,
        uint256 amountIn,
        uint256 minAmountOut,
        address[] calldata path
    ) external onlyRole(CIRCUIT_BREAKER_ROLE) nonReentrant returns (uint256 amountOut) {
        require(block.timestamp - lastBuyBackAt[tokenIn] >= buyBackCooldown, "COOLDOWN");
        require(path.length >= 2, "path length");
        require(path[0] == tokenIn, "path[0] != tokenIn");
        require(path[path.length - 1] == protocolToken, "path end != protocolToken");

        Balances storage bal = _tokenBalances[tokenIn];
        require(amountIn <= bal.liquidity, "insufficient reserve");
        bal.liquidity -= uint128(amountIn);

        if (IERC20(tokenIn).allowance(address(this), address(router)) < amountIn) {
            IERC20(tokenIn).safeIncreaseAllowance(address(router), amountIn);
        }

        uint256[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            minAmountOut,
            path,
            address(this),
            block.timestamp + 900
        );
        amountOut = amounts[amounts.length - 1];

        emit BuyBackExecuted(tokenIn, amountIn, amountOut, bal.liquidity);
        lastBuyBackAt[tokenIn] = block.timestamp;
    }

    /*────────────────────────── Compensation ──────────────────*/

    /**
     * @notice Pay out compensation from the **compensation** bucket.
     * @param token  ERC20 token address or address(0) for native ETH.
     * @param to     Recipient address.
     * @param amount Amount to send.
     *
     * @dev Only GUARDIAN_ROLE; non-reentrant. Emits `CompensationPaid`.
     *
     * @custom:reverts exceeds compensation reserve if `amount > compensation bucket`
     */
    function payCompensation(address token, address to, uint256 amount)
        external
        onlyRole(GUARDIAN_ROLE)
        nonReentrant
    {
        Balances storage bal = _tokenBalances[token];
        require(amount <= bal.compensation, "exceeds compensation reserve");
        bal.compensation -= uint128(amount);
        _sendToken(token, to, amount);
        emit CompensationPaid(token, to, amount);
    }

    /*────────────────────────── Bucket Sweep / Re-alloc ───────*/

    /**
     * @notice Move funds between buckets for `token`.
     * @param token          ERC20 token address or address(0) for native ETH.
     * @param amount         Amount to move.
     * @param toCompensation If true, move from liquidity → compensation; else the opposite.
     *
     * @dev Only GUARDIAN_ROLE. Emits `Sweep`.
     *
     * @custom:reverts exceeds liquidity/compensation if `amount` exceeds source bucket
     */
    function sweep(address token, uint256 amount, bool toCompensation) external onlyRole(GUARDIAN_ROLE) {
        Balances storage bal = _tokenBalances[token];
        if (toCompensation) {
            require(amount <= bal.liquidity, "exceeds liquidity");
            bal.liquidity -= uint128(amount);
            bal.compensation += uint128(amount);
        } else {
            require(amount <= bal.compensation, "exceeds compensation");
            bal.compensation -= uint128(amount);
            bal.liquidity += uint128(amount);
        }
        emit Sweep(token, amount, toCompensation);
    }

    /*────────────────────────── Views ─────────────────────────*/

    /**
     * @notice Read the liquidity bucket for `token`.
     * @param token ERC20 token address or address(0) for native ETH.
     * @return uint256 Current liquidity balance.
     */
    function liquidityOf(address token) external view returns (uint256) {
        return _tokenBalances[token].liquidity;
    }

    /**
     * @notice Read the compensation bucket for `token`.
     * @param token ERC20 token address or address(0) for native ETH.
     * @return uint256 Current compensation balance.
     */
    function compensationOf(address token) external view returns (uint256) {
        return _tokenBalances[token].compensation;
    }

    /*────────────────────────── Internal utils ────────────────*/

    /**
     * @notice Collect tokens/ETH from caller.
     * @param token  ERC20 token address or address(0) for native ETH.
     * @param amount Expected amount to receive.
     *
     * @dev For ETH, requires `msg.value == amount`. For ERC20, requires `msg.value == 0`
     *      and pulls tokens from `_msgSender()` via `safeTransferFrom`.
     *
     * @custom:reverts ETH amount mismatch if `msg.value != amount` for ETH
     * @custom:reverts unexpected ETH       if `msg.value != 0` for ERC20 deposits
     */
    function _receiveToken(address token, uint256 amount) internal {
        if (token == address(0)) {
            require(msg.value == amount, "ETH amount mismatch");
        } else {
            require(msg.value == 0, "unexpected ETH");
            IERC20(token).safeTransferFrom(_msgSender(), address(this), amount);
        }
    }

    /**
     * @notice Send tokens/ETH to `to`.
     * @param token  ERC20 token address or address(0) for native ETH.
     * @param to     Recipient.
     * @param amount Amount to send.
     */
    function _sendToken(address token, address to, uint256 amount) internal {
        if (token == address(0)) {
            payable(to).transfer(amount);
        } else {
            IERC20(token).safeTransfer(to, amount);
        }
    }

    /*────────────────────────── Pause / Upgrade ───────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }

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

    /**
     * @notice Accept native ETH and credit to the **compensation** bucket.
     * @dev Emits `CompensationFunded(address(0), msg.value)`.
     */
    receive() external payable {
        _tokenBalances[address(0)].compensation += uint128(msg.value);
        emit CompensationFunded(address(0), msg.value);
    }

    /// @dev Storage gap reserved for future upgrades.
    uint256[44] private __gap;
}

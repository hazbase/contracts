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

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/// @dev ReservePool subset used by Splitter when routing ERC-20 to contract destinations.
interface IReservePool {
    function fundCompensation(address token, uint256 amount) external payable;
    function fundLiquidity(address token, uint256 amount) external payable;
}

enum ReserveBucket {
    Direct,
    Compensation,
    Liquidity
}

/**
 * @title Splitter
 *
 * @notice
 * - Purpose: Role-governed **fee splitter** that distributes incoming assets (ERC-20 or native ETH)
 *   across a set of routes expressed in **basis points** (sum = 10,000). Destinations can be EOAs
 *   or **ReservePool** contracts. For native sends that fail (e.g., a non-payable recipient), the
 *   amount is recorded as **pending** and can be claimed or swept later.
 *
 * - Features:
 *   * ERC-20 path is **fee-on-transfer safe** by measuring actual received tokens.
 *   * ReservePool routes can explicitly target the `compensation` or `liquidity` bucket.
 *   * Native path records failed deliveries into the **pending** ledger for later claim/sweep.
 *   * Routes are updatable by `GOVERNOR_ROLE`. Pausable, UUPS upgradeable, ERC-2771 meta-tx.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Route validity: `_setRoutes` enforces 1..10 entries and bps sum = 10,000.
 * - Distribution order: indices 1..N-1 are paid exact bps; **index 0 receives remainder** (absorbs dust).
 * - ERC-20 approvals: when sending to ReservePool, allowance is increased only as needed.
 * - Native delivery: `call` is used; on failure, credits `pendingNative[dest]`.
 * - Access control: `GOVERNOR_ROLE` (set routes / sweep pending / upgrade), `PAUSER_ROLE` (pause).
 */

contract Splitter is
    RolesCommonUpgradeable,
    ERC2771ContextUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // Types and storage

    /// @notice A single route (recipient + share).
    /// @param dest Recipient address (EOA or ReservePool).
    /// @param bps Share in basis points (1..10,000). Sum of all routes must be 10,000.
    /// @param reserveBucket For ReservePool destinations: direct fallback, compensation bucket, or liquidity bucket.
    struct Route {
        address       dest;
        uint16        bps;
        ReserveBucket reserveBucket;
    }

    /// @notice Current active routes. Ordering matters: index 0 receives **remainder**.
    Route[] public routes;

    /// @notice Native currency amounts that could not be delivered (by recipient address).
    mapping(address => uint256) public pendingNative;

    // Events

    /// @notice Emitted after a split operation for ERC-20 or native path.
    event FeeSplit(uint256 total, address indexed asset, bool nativePath);

    /// @notice Emitted after routes are updated by governance.
    event RoutesUpdated();

    /// @notice Emitted when native payment fails and the value is recorded as pending.
    event NativePending(address indexed dest, uint256 amount);

    /// @notice Emitted when a pending native balance is claimed or swept.
    event PendingClaimed(address indexed dest, uint256 amount);

    // Initializer

    /// @notice Initialize the splitter with routes and meta-tx forwarders.
    /// @param admin Admin address for RolesCommon (governs roles per your setup).
    /// @param _routes Initial route array (1..10 items, sum of bps = 10,000).
    /// @param forwarders Trusted ERC-2771 forwarders for meta-transactions.
    /// @dev Calls the OZ-style upgradeable initializers and validates routes via `_setRoutes`.
    function initialize(
        address admin,
        Route[] calldata _routes,
        address[] calldata forwarders
    ) external initializer {
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        _setRoutes(_routes);
    }

    // ERC-20 path

    /// @notice Split an incoming ERC-20 amount across routes.
    /// @param token ERC-20 token to distribute.
    /// @param amount Nominal amount expected from the caller.
    /// @dev Pulls `amount` via `safeTransferFrom`, then measures the actual received amount
    /// so fee-on-transfer tokens are handled safely before distribution.
    /// @custom:reverts zero amt if `amount == 0`
    /// @custom:reverts no tokens if transfer yields zero balance increase
    function routeERC20(IERC20 token, uint256 amount) external nonReentrant {
        require(amount > 0, "zero amt");
        uint256 balBefore = token.balanceOf(address(this));
        token.safeTransferFrom(_msgSender(), address(this), amount);
        uint256 balAfter = token.balanceOf(address(this));
        uint256 received = balAfter - balBefore; // actual tokens received
        require(received > 0, "no tokens");
        _distributeToken(token, received);
        emit FeeSplit(received, address(token), false);
    }

    /// @notice Sweep entire ERC20 balance held by this contract and split by current routes.
    /// @dev Permissionless trigger: anyone can call to distribute already-held balances.
    /// Remainder handling is delegated to `_distributeToken`, where index 0 receives the residue by design.
    function sweepERC20(IERC20 token) external nonReentrant {
        uint256 bal = token.balanceOf(address(this));
        if (bal == 0) return;
        _distributeToken(token, bal);
        emit FeeSplit(bal, address(token), false);
    }

    // Native path

    /// @notice Split native ETH across routes.
    /// @dev Calls `_distributeNative(msg.value)` and emits `FeeSplit`.
    /// @custom:reverts zero value if `msg.value == 0`
    function routeNative() external payable nonReentrant {
        require(msg.value > 0, "zero value");
        _distributeNative(msg.value);
        emit FeeSplit(msg.value, address(0), true);
    }

    // Governance: routes

    /// @notice Update routes (governance).
    /// @param _routes New route set (1..10 entries; sum of bps must equal 10,000).
    /// @dev Only `GOVERNOR_ROLE`. Delegates validation to `_setRoutes`.
    function setRoutes(Route[] calldata _routes) external onlyRole(GOVERNOR_ROLE) {
        _setRoutes(_routes);
    }

    // Pending native

    /// @notice Claim your pending native balance accrued from previous failed deliveries.
    /// @dev Sends current `pendingNative[msg.sender]` and emits `PendingClaimed`.
    /// @custom:reverts no pending if caller has no pending balance
    function claimPendingNative() external nonReentrant {
        uint256 amt = pendingNative[_msgSender()];
        require(amt > 0, "no pending");
        pendingNative[_msgSender()] = 0;
        _safeNativeSendOrPend(Route({ dest: _msgSender(), bps: 10000, reserveBucket: ReserveBucket.Direct }), amt);
        emit PendingClaimed(_msgSender(), amt);
    }

    /// @notice Sweep a specific amount from `dest`'s pending native to the same `dest`.
    /// @param dest Destination whose pending balance to sweep.
    /// @param amount Amount to sweep (<= pendingNative[dest]).
    /// @dev Only `GOVERNOR_ROLE`. Reuses `_safeNativeSendOrPend` and emits `PendingClaimed`.
    /// @custom:reverts exceed if `amount > pendingNative[dest]`
    function sweepPendingNative(address dest, uint256 amount) external onlyRole(GOVERNOR_ROLE) nonReentrant {
        require(pendingNative[dest] >= amount, "exceed");
        pendingNative[dest] -= amount;
        _safeNativeSendOrPend(Route({ dest: dest, bps: 10000, reserveBucket: ReserveBucket.Direct }), amount);
        emit PendingClaimed(dest, amount);
    }

    // Internal helpers: ERC-20

    /// @notice Send ERC-20 according to the route definition, preferring ReservePool API and falling back to transfer.
    /// @param route Route metadata.
    /// @param token ERC-20 token to send.
    /// @param amt Amount to send.
    /// @dev If `route.dest` is a contract and the route selects a ReservePool bucket, this tries the
    /// corresponding ReservePool funding call first and falls back to `safeTransfer` on failure.
    function _sendReservePoolOrDirect(Route memory route, IERC20 token, uint256 amt) internal {
        address dest = route.dest;
        if (dest.code.length > 0) {
            if (route.reserveBucket != ReserveBucket.Direct) {
                if (token.allowance(address(this), dest) < amt) {
                    token.safeIncreaseAllowance(dest, amt);
                }

                if (route.reserveBucket == ReserveBucket.Compensation) {
                    try IReservePool(dest).fundCompensation(address(token), amt) { return; }
                    catch {}
                } else if (route.reserveBucket == ReserveBucket.Liquidity) {
                    try IReservePool(dest).fundLiquidity(address(token), amt) { return; }
                    catch {}
                }
            }
            token.safeTransfer(dest, amt);
        } else {
            token.safeTransfer(dest, amt);
        }
    }

    /// @notice Distribute ERC-20 `actualAmount` across `routes` with running-sum remainder to index 0.
    /// @param token ERC-20 token.
    /// @param actualAmount Amount to distribute (already measured).
    /// @dev If only one route exists, the full amount goes there. Otherwise indices 1..N-1 receive
    /// exact bps shares and index 0 receives the remainder so dust never escapes the route set.
    function _distributeToken(IERC20 token, uint256 actualAmount) internal {
        uint256 len = routes.length;
        if (len == 1) {
            _sendReservePoolOrDirect(routes[0], token, actualAmount);
        } else {
            uint256 distributed;
            for (uint256 i = 1; i < len; ++i) {
                uint256 share = (actualAmount * routes[i].bps) / 10000;
                if (share == 0) continue;
                _sendReservePoolOrDirect(routes[i], token, share);
                unchecked { distributed += share; }
            }
            uint256 remainder = actualAmount - distributed; // includes all dust
            _sendReservePoolOrDirect(routes[0], token, remainder);
        }
    }

    // Internal helpers: native

    /// @notice Distribute native ETH `amount` across routes (remainder to index 0).
    /// @param amount Amount of ETH to distribute (wei).
    /// @dev Uses `_safeNativeSendOrPend` for delivery and accrues failed sends into `pendingNative`.
    function _distributeNative(uint256 amount) internal {
        uint256 len = routes.length;
        if (len == 1) {
            _safeNativeSendOrPend(routes[0], amount);
        } else {
            uint256 distributed;
            for (uint256 i = 1; i < len; ++i) {
                uint256 share = (amount * routes[i].bps) / 10000;
                if (share == 0) continue;
                _safeNativeSendOrPend(routes[i], share);
                unchecked { distributed += share; }
            }
            uint256 remainder = amount - distributed;
            _safeNativeSendOrPend(routes[0], remainder);
        }
    }

    /// @notice Attempt to deliver native ETH; on failure, record as pending for later claim.
    /// @param route Route metadata.
    /// @param value Amount of ETH to send (wei).
    function _safeNativeSendOrPend(Route memory route, uint256 value) private {
        address dest = route.dest;
        bool ok;

        if (route.reserveBucket == ReserveBucket.Compensation) {
            (ok, ) = dest.call{value: value}(
                abi.encodeWithSignature(
                    "fundCompensation(address,uint256)",
                    address(0),
                    value
                )
            );
        } else if (route.reserveBucket == ReserveBucket.Liquidity) {
            (ok, ) = dest.call{value: value}(
                abi.encodeWithSignature(
                    "fundLiquidity(address,uint256)",
                    address(0),
                    value
                )
            );
        } else {
            (ok, ) = dest.call{value: value}("");
        }

        if (!ok) {
            pendingNative[dest] += value;
            emit NativePending(dest, value);
        }
    }

    // Route validation

    /// @notice Validate and set the route array.
    /// @param _routes New routes to activate (1..10 entries; each bps in [1, 10,000]).
    /// @dev Clears previous routes, validates each entry, enforces sum == 10,000, then stores.
    /// @custom:reverts len if `_routes.length == 0` or `> 10`
    /// @custom:reverts zero dest if any `dest == address(0)`
    /// @custom:reverts bps if any `bps == 0` or `> 10,000`
    /// @custom:reverts bucket if reserveBucket is outside the known enum range
    /// @custom:reverts sum!=100% if total bps != 10,000
    function _setRoutes(Route[] calldata _routes) internal {
        require(_routes.length > 0 && _routes.length <= 10, "len");
        uint256 sum;
        delete routes;
        for (uint256 i; i < _routes.length; ++i) {
            require(_routes[i].dest != address(0), "zero dest");
            require(_routes[i].bps > 0 && _routes[i].bps <= 10000, "bps");
            require(uint8(_routes[i].reserveBucket) <= uint8(ReserveBucket.Liquidity), "bucket");
            sum += _routes[i].bps;
            routes.push(_routes[i]);
        }
        require(sum == 10000, "sum!=100%");
        emit RoutesUpdated();
    }

    // Pause control

    /// @notice Pause state-changing entrypoints; only PAUSER_ROLE.
    function pause()   external onlyRole(PAUSER_ROLE) { _pause();   }

    /// @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // meta-tx ---------------------------------------------------------------

    /// @dev ERC-2771 meta-tx sender override.
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /// @dev ERC-2771 meta-tx data override.
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    // Upgrade authorization

    /// @notice Authorize UUPS upgrade; only `GOVERNOR_ROLE`.
    /// @param newImpl Proposed implementation address (unused; validation is role-based).
    function _authorizeUpgrade(address newImpl) internal override onlyRole(GOVERNOR_ROLE) {}

    // ETH receive path

    /// @notice Receive hook: auto-distribute directly sent ETH using current routes.
    /// @dev Ignores zero-value transfers or when no routes are configured and emits `FeeSplit` after distribution.
    receive() external payable {
        if (msg.value == 0 || routes.length == 0) return;
        _distributeNative(msg.value);
        emit FeeSplit(msg.value, address(0), true);
    }
}

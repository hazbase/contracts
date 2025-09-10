// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.28;

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
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";

/**
 * @title SmartAccount
 *
 * @notice
 * - Purpose: Minimal, upgradeable **Account Abstraction** (ERC-4337–style) smart-account
 *   with owner EOA, optional guardian-based recovery, limited-lifespan **session keys**,
 *   execution helpers (call/batch/delegatecall with whitelist), and UUPS upgrades governed by `safe`.
 *
 * - Feature highlights:
 *   * **ERC-4337** validation via `validateUserOp`/_validateSignature (owner or session key).
 *   * **Guardian recovery**: 2-step owner rotation with time delay (two-of-N attestation enforced off-chain).
 *   * **Session keys**: TTL, per-key call quotas, and selector mask gating.
 *   * **Delegatecall whitelist** for extension modules (mitigates arbitrary delegatecall risk).
 *   * **UUPS** upgradeable; upgrade authority gated by `safe`.
 *   * **Pausable**; execution paths are blocked when paused.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Signature scheme: userOp signature is verified over `eth_sign` style (toEthSignedMessageHash(userOpHash));
 *   adjust if switching to EIP-712 at the bundler layer.
 * - Session key selector mask: `(selector & mask) == selector` allows grouping permitted selectors by mask.
 * - Delegatecall: only targets whitelisted via `whitelistImpl`; whitelist governance is `onlySafe`.
 * - Reentrancy: execution functions are `nonReentrant`. External calls are performed after gating checks.
 * - Funds: `validateUserOp` forwards missing funds to EntryPoint using a raw call; verify EntryPoint assumptions.
 */

/*────────────────────────── UserOperation (local mirror) ─────────────────────────*/
/**
 * @dev Minimal local mirror of ERC-4337 UserOperation for signature validation.
 */
struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerificationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

/*────────────────────────── Smart-Account Logic ─────────────────────────*/
contract SmartAccount is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev Constant returned to EntryPoint when signature verification fails.
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /*────────────────────────── State ─────────────────────────*/

    /// @notice EOA that controls the account (direct signer validation).
    address public owner;

    /// @notice Gnosis Safe (or similar) that governs upgrades / admin-only operations.
    address public safe;

    /// @dev EntryPoint used for ERC-4337 flows.
    IEntryPoint private _entryPoint;

    // ── Guardian recovery (two-step with delay) ──
    EnumerableSet.AddressSet private _guardians;
    uint256 public guardianChangeAfter;  // when the pending owner can accept
    address public pendingOwner;
    uint256 public constant RECOVERY_DELAY = 2 days;

    // ── Session key structure ──
    /**
     * @dev Session key controlling limited capability.
     * - `validUntil`   : epoch timestamp; 0 means disabled.
     * - `callLimit`    : max calls allowed.
     * - `usedCalls`    : calls already consumed (auto-revokes on reaching limit).
     * - `selectorMask` : bitmask to gate allowed function selectors (sel & mask == sel).
     */
    struct Session {
        uint64  validUntil;
        uint64  callLimit;
        uint64  usedCalls;
        bytes4  selectorMask;
    }
    /// @notice Mapping of session keys to session data.
    mapping(address => Session) public sessionKeys;

    /// @notice Delegatecall whitelist (impl address => allowed?).
    mapping(address => bool) public isWhitelistedImpl;

    /*────────────────────────── Events ───────────────────────*/

    event OwnerChangeRequested(address indexed newOwner, uint256 executeAfter);
    event OwnerChanged(address indexed newOwner);
    event GuardianAdded(address indexed g);
    event GuardianRemoved(address indexed g);
    event SessionKeyAdded(address indexed k, Session s);
    event SessionKeyRevoked(address indexed k);
    event ImplWhitelisted(address indexed impl, bool allowed);

    /*────────────────────────── Initializer ───────────────────*/

    /**
     * @notice Initialize the SmartAccount.
     * @param _owner  EOA that controls the account.
     * @param _entry  EntryPoint address used for ERC-4337 flows.
     * @param _safe   Admin authority (governs upgrades/pausing/whitelisting via onlySafe).
     *
     * @dev Sets owner/safe/entryPoint; initializes UUPS, ReentrancyGuard, and Pausable.
     *
     * @custom:reverts zero if `_owner == 0` or `_safe == 0`
     */
    function initialize(address _owner, address _entry, address _safe) external initializer {
        require(_owner != address(0) && _safe != address(0), "zero");
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();
        owner = _owner;
        safe  = _safe;
        _entryPoint = IEntryPoint(_entry);
    }

    /*────────────────────────── Modifiers ─────────────────────*/

    /// @notice Restrict to owner EOA.
    modifier onlyOwner()    { require(msg.sender == owner, "not-owner"); _; }
    /// @notice Restrict to admin `safe`.
    modifier onlySafe()     { require(msg.sender == safe,  "not-safe");  _; }
    /// @notice Restrict to EntryPoint context in ERC-4337 flow.
    modifier onlyEntryPoint() {
        require(msg.sender == address(_entryPoint), "not-ep");
        _;
    }

    /*────────────────────────── EntryPoint view ───────────────*/

    /**
     * @notice Expose the configured EntryPoint for AA SDKs.
     * @return IEntryPoint Current EntryPoint instance.
     */
    function entryPoint() external view returns (IEntryPoint) { return _entryPoint; }

    /*────────────────────────── Guardian Recovery ─────────────*/

    /**
     * @notice Add a guardian address.
     * @param g Guardian address to add.
     *
     * @dev Only owner. Emits `GuardianAdded`.
     */
    function addGuardian(address g) external onlyOwner { _guardians.add(g); emit GuardianAdded(g);}    

    /**
     * @notice Remove a guardian address.
     * @param g Guardian address to remove.
     *
     * @dev Only owner. Emits `GuardianRemoved`.
     */
    function removeGuardian(address g) external onlyOwner { _guardians.remove(g); emit GuardianRemoved(g);}    

    /**
     * @notice Guardians propose a new owner (off-chain two-of-N validation recommended).
     * @param newOwner Candidate owner address (non-zero).
     *
     * @dev
     * - Must be called by a registered guardian.
     * - Starts the recovery delay (`RECOVERY_DELAY`) after which the `pendingOwner` may accept.
     * - Emits `OwnerChangeRequested`.
     *
     * @custom:reverts owner-0  if `newOwner == 0`
     * @custom:reverts not-guardian if caller is not registered
     * @custom:reverts pending  if there is already a pending change
     */
    function proposeOwner(address newOwner) external {
        require(newOwner!=address(0),"owner-0");
        require(_guardians.contains(msg.sender), "not-guardian");
        require(guardianChangeAfter == 0, "pending");

        pendingOwner = newOwner;
        guardianChangeAfter = block.timestamp + RECOVERY_DELAY;
        emit OwnerChangeRequested(newOwner, guardianChangeAfter);
    }

    /**
     * @notice Accept pending ownership after the delay window.
     *
     * @dev Only the `pendingOwner` can accept. Resets pending state and emits `OwnerChanged`.
     *
     * @custom:reverts delay        if now < `guardianChangeAfter` or none pending
     * @custom:reverts not-pending  if caller is not `pendingOwner`
     */
    function acceptOwner() external {
        require(block.timestamp >= guardianChangeAfter && guardianChangeAfter!=0, "delay");
        require(msg.sender == pendingOwner, "not-pending");
        owner = pendingOwner;
        pendingOwner = address(0);
        guardianChangeAfter = 0;
        emit OwnerChanged(owner);
    }

    /*────────────────────────── Session Keys ──────────────────*/

    /**
     * @notice Add or refresh a session key.
     * @param k            Session key address.
     * @param ttl          Time-to-live in seconds (from now).
     * @param callLimit    Max number of calls allowed for this key (>0).
     * @param selectorMask Bitmask of allowed selectors (sel & mask == sel).
     *
     * @dev Only owner. Emits `SessionKeyAdded`.
     *
     * @custom:reverts limit0 if `callLimit == 0`
     * @custom:reverts ttl-ov if `block.timestamp + ttl` overflows uint64
     */
    function addSessionKey(address k, uint64 ttl, uint64 callLimit, bytes4 selectorMask) external onlyOwner {
        require(callLimit > 0, "limit0");
        require(ttl <= type(uint64).max - block.timestamp, "ttl-ov");
        sessionKeys[k] = Session(uint64(block.timestamp)+ttl, callLimit, 0, selectorMask);
        emit SessionKeyAdded(k, sessionKeys[k]);
    }

    /**
     * @notice Revoke a session key immediately.
     * @param k Session key address to revoke.
     *
     * @dev Only owner. Emits `SessionKeyRevoked`.
     */
    function revokeSessionKey(address k) external onlyOwner {
        delete sessionKeys[k];
        emit SessionKeyRevoked(k);
    }

    /*────────────────────────── ERC-4337 Validation ───────────*/

    /**
     * @notice Internal signer validation for ERC-4337 flow (owner or an active session key).
     * @param userOp     The incoming UserOperation (signature is `(ownerSig, reserved)` ABI-encoded).
     * @param userOpHash Hash computed by the EntryPoint for this userOp.
     * @return validationData 0 if owner signature; else packed `validUntil<<160` for session key;
     *                        or `SIG_VALIDATION_FAILED (1)` on failure.
     *
     * @dev
     * - Owner path: verify `sigOwner` over `toEthSignedMessageHash(userOpHash)`.
     * - Session path: check TTL, call quota, and `selectorMask`. On final allowed call, auto-revoke.
     * - NOTE: Signature layout is `(bytes sigOwner, bytes reserved)` to allow future extensibility.
     *
     * @custom:reverts cd<4  if `userOp.callData` is shorter than 4-byte selector
     * @custom:reverts sig<96 if `userOp.signature` is too short to contain `(r,s,v)`-style bytes
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        returns (uint256 validationData)
    {
        require(userOp.callData.length >= 4, "cd<4");
        require(userOp.signature.length >= 96, "sig<96");

        (bytes memory sigOwner,) = abi.decode(userOp.signature,(bytes,bytes));
        address signer = ECDSA.recover(
            MessageHashUtils.toEthSignedMessageHash(userOpHash),
            sigOwner
        );

        if (signer == owner) {
            return 0;
        }

        Session storage s = sessionKeys[signer];

        bytes4 sel = bytes4(userOp.callData);
        bool selectorOK = (sel & s.selectorMask) == sel;

        if (
            s.validUntil   >= block.timestamp &&
            s.usedCalls    <  s.callLimit &&
            selectorOK
        ) {
            unchecked { ++s.usedCalls; }
            if (s.usedCalls >= s.callLimit) {
                delete sessionKeys[signer];
                emit SessionKeyRevoked(signer);
            }

            validationData = uint256(s.validUntil) << 160; // pack in OZ/EP format: validUntil in high bits
            return validationData;
        }

        return SIG_VALIDATION_FAILED;
    }

    /**
     * @notice ERC-4337 `validateUserOp` entry. Verifies signature and funds EntryPoint if requested.
     * @param userOp               The UserOperation.
     * @param userOpHash           Hash computed by EntryPoint.
     * @param missingAccountFunds  Amount the account should deposit to the EntryPoint.
     * @return validationData      0 (owner), packed session validity, or `SIG_VALIDATION_FAILED (1)`.
     *
     * @dev Only EntryPoint may call. If `missingAccountFunds > 0`, forwards ETH to EntryPoint using a raw call.
     *
     * @custom:reverts only entrypoint if caller is not the configured EntryPoint
     * @custom:reverts deposit fail   if funding transfer to EntryPoint fails
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256 validationData)
    {
        require(msg.sender == address(_entryPoint), "only entrypoint");
        
        validationData = _validateSignature(userOp, userOpHash);

        if (missingAccountFunds > 0) {
            (bool ok, ) = address(_entryPoint).call{value: missingAccountFunds}("");
            require(ok, "deposit fail");
        }
    }

    /*────────────────────────── Execution Helpers ─────────────*/

    /**
     * @notice Execute a low-level call from the account.
     * @param to    Target address.
     * @param value ETH value to send.
     * @param data  Calldata to forward.
     *
     * @dev Only EntryPoint; respects pause & nonReentrancy. Reverts bubbling failure data if any.
     *
     * @custom:reverts exec-fail if the external call fails
     */
    function execute(address to,uint256 value,bytes calldata data) external onlyEntryPoint whenNotPaused nonReentrant {
        (bool ok,) = to.call{value:value}(data);
        require(ok,"exec-fail");
    }

    /**
     * @notice Execute a batch of calls atomically.
     * @param to     Array of target addresses.
     * @param values Array of ETH values (one per target).
     * @param data   Array of calldata blobs (one per target).
     *
     * @dev Only EntryPoint; reverts on the first failed call bubbling its returndata.
     *
     * @custom:reverts len if array lengths mismatch
     */
    function executeBatch(
        address[] calldata to,
        uint256[] calldata values,
        bytes[] calldata data
    ) external onlyEntryPoint whenNotPaused nonReentrant {
        uint256 len = to.length;
        require(len == data.length && len == values.length, "len");

        for (uint256 i; i < len; ++i) {
            (bool ok, bytes memory ret) = to[i].call{value: values[i]}(data[i]);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
    }

    /**
     * @notice Execute a whitelisted **delegatecall** against `impl`.
     * @param impl  Implementation address (must be whitelisted).
     * @param data  Calldata for the delegatecall.
     *
     * @dev Only EntryPoint. Reverts if `impl` is not whitelisted (`isWhitelistedImpl[impl]`).
     *      Bubbles revert data from the callee.
     *
     * @custom:reverts impl-not-allowed if target not whitelisted
     */
    function executeDelegate(address impl, bytes calldata data) external onlyEntryPoint whenNotPaused nonReentrant {
        require(isWhitelistedImpl[impl],"impl-not-allowed");
        (bool ok, bytes memory ret) = impl.delegatecall(data);
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    /*────────────────────────── Admin (onlySafe) ─────────────*/

    /**
     * @notice Whitelist or remove a delegatecall target implementation.
     * @param impl    Implementation address.
     * @param allowed True to allow delegatecall to `impl`, false to revoke.
     *
     * @dev Only `safe`. Emits `ImplWhitelisted`.
     */
    function whitelistImpl(address impl,bool allowed) external onlySafe {
        isWhitelistedImpl[impl]=allowed;
        emit ImplWhitelisted(impl,allowed);
    }

    /**
     * @notice Pause execution helpers; only `safe`.
     */
    function pause() external onlySafe { _pause(); }

    /**
     * @notice Unpause execution helpers; only `safe`.
     */
    function unpause() external onlySafe { _unpause(); }

    /*────────────────────────── UUPS Upgrade Auth ────────────*/

    /**
     * @notice Authorize UUPS upgrade; only the `safe` may upgrade, and only via proxy.
     * @param newImpl Proposed new implementation address.
     *
     * @dev Uses OZ `onlyProxy` to disallow direct logic calls; no additional checks here.
     */
    function _authorizeUpgrade(address newImpl) internal override onlySafe onlyProxy {}

    /*────────────────────────── ERC-1271 ─────────────────────*/

    /**
     * @notice ERC-1271 signature validation for off-chain integrations.
     * @param hash       Message hash.
     * @param signature  ECDSA signature to verify.
     * @return bytes4    `0x1626ba7e` on success, `0xffffffff` on failure.
     *
     * @dev Validates against `owner` using `toEthSignedMessageHash`.
     */
    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4){
        return (ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(hash), signature) == owner) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    /**
     * @notice Accept ETH deposits (e.g., to fund EntryPoint fees); blocked when paused.
     */
    receive() external payable { require(!paused(), "paused"); }
}

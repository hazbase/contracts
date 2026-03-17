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
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

import {IEntryPoint} from "@account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {IOwnerValidator} from "./interfaces/IOwnerValidator.sol";

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

/**
 * @title SmartAccount
 *
 * @notice
 * - Purpose: upgradeable ERC-4337 smart account with passkey-validator owner,
 *   threshold guardian recovery, capability-scoped session keys, and allowlisted delegatecall extensions.
 * - Owner operations are validated via `ownerValidator + ownerConfigHash`.
 * - Session keys remain intended for short-lived, first-party `L1-L2` actions with on-chain
 *   target/selector/value/batch constraints.
 *
 * @dev
 * - Owner calls are expected to route through `execute(address(this), ...)` so that account
 *   management remains self-authorized rather than `msg.sender == owner` authorized.
 * - Session targets must be approved by both the account owner flow and the `safe` role.
 * - `executeDelegate` remains unavailable to session keys.
 */
contract SmartAccount is
    Initializable,
    UUPSUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @dev ERC-4337 validation failure sentinel used by the EntryPoint flow.
    uint256 internal constant SIG_VALIDATION_FAILED = 1;
    /// @dev Signature envelope type for owner-scoped operations validated via `ownerValidator`.
    uint256 internal constant SIG_TYPE_OWNER = 0;
    /// @dev Signature envelope type for short-lived session-key operations.
    uint256 internal constant SIG_TYPE_SESSION = 1;

    /// @notice Mandatory delay between guardian recovery proposal and acceptance.
    uint256 public constant RECOVERY_DELAY = 2 days;

    /// @notice Validator contract responsible for proving owner-scoped operations.
    address public ownerValidator;
    /// @notice Commitment to the validator-specific owner configuration for the current owner.
    bytes32 public ownerConfigHash;
    /// @notice Operational safe allowed to manage emergency and session-safe policy controls.
    address public safe;
    IEntryPoint private _entryPoint;

    EnumerableSet.AddressSet private _guardians;
    /// @notice Guardian approvals required before a pending recovery can be accepted.
    uint256 public recoveryThreshold;
    /// @notice Monotonic identifier for recovery attempts; used to prevent replay across guardian-set changes.
    uint256 public recoveryNonce;

    /// @notice Pending owner rotation proposed through guardian recovery.
    /// @dev Recovery is expressed in validator/config-hash terms so the account can move between owner schemes
    /// without assuming the owner is always a plain address.
    struct RecoveryRequest {
        address pendingOwnerValidator;
        bytes32 pendingOwnerConfigHash;
        uint64 executeAfter;
        uint32 approvals;
        uint64 nonce;
        bool active;
    }

    RecoveryRequest public recoveryRequest;
    mapping(uint256 => mapping(address => bool)) private _recoveryApprovals;

    /// @notice Short-lived capability grant for first-party `L1-L2` session actions.
    /// @dev Session permissions are intentionally coarse at the key level and fine-grained through
    /// target/selector allowlists plus value/batch constraints stored in separate mappings.
    struct SessionConfig {
        uint64 validUntil;
        uint64 callLimit;
        uint64 usedCalls;
        uint64 version;
        uint64 maxBatchCalls;
        uint128 maxValuePerCall;
        uint128 maxTotalValuePerUserOp;
        bool allowBatch;
    }

    mapping(address => SessionConfig) public sessionConfigs;
    mapping(address => uint64) private _sessionVersions;
    mapping(address => mapping(uint64 => mapping(address => bool))) private _sessionTargets;
    mapping(address => mapping(uint64 => mapping(address => mapping(bytes4 => bool)))) private _sessionSelectors;

    mapping(address => bool) public isSessionSafeTarget;
    mapping(address => bool) public isWhitelistedImpl;

    event OwnerConfigUpdated(address indexed validator, bytes32 indexed ownerConfigHash);
    event GuardianAdded(address indexed guardian);
    event GuardianRemoved(address indexed guardian);
    event GuardianThresholdUpdated(uint256 threshold);
    event RecoveryProposed(address indexed guardian, address indexed validator, bytes32 indexed ownerConfigHash, uint256 executeAfter, uint256 nonce);
    event RecoveryApproved(address indexed guardian, address indexed validator, bytes32 indexed ownerConfigHash, uint256 approvals, uint256 nonce);
    event RecoveryCancelled(uint256 nonce);
    event SessionKeyGranted(address indexed key, SessionConfig config);
    event SessionKeyRevoked(address indexed key, uint64 version);
    event SessionTargetSet(address indexed key, uint64 indexed version, address indexed target, bool allowed);
    event SessionSelectorSet(address indexed key, uint64 indexed version, address indexed target, bytes4 selector, bool allowed);
    event SessionSafeTargetSet(address indexed target, bool allowed);
    event ImplWhitelisted(address indexed impl, bool allowed);

    /// @notice Initializes a freshly cloned account with validator-based ownership.
    /// @dev This function is intended to be called exactly once by the factory during clone creation.
    /// The owner config stays opaque to the account itself; only the validator decides how it is hashed.
    /// @param _ownerValidator Validator used for owner-scoped user operations and ERC-1271 checks.
    /// @param _ownerConfig Validator-specific owner configuration bytes.
    /// @param _entry ERC-4337 EntryPoint used by this account.
    /// @param _safe Operational safe that can manage emergency controls and session-safe targets.
    function initialize(address _ownerValidator, bytes calldata _ownerConfig, address _entry, address _safe) external initializer {
        require(_ownerValidator != address(0) && _safe != address(0), "zero");
        require(_ownerConfig.length > 0, "owner-config0");
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __Pausable_init();

        ownerValidator = _ownerValidator;
        ownerConfigHash = IOwnerValidator(_ownerValidator).configHash(_ownerConfig);
        safe = _safe;
        _entryPoint = IEntryPoint(_entry);
        recoveryThreshold = 2;

        emit GuardianThresholdUpdated(2);
        emit OwnerConfigUpdated(_ownerValidator, ownerConfigHash);
    }

    modifier onlySafe() {
        require(msg.sender == safe, "not-safe");
        _;
    }

    modifier onlySelf() {
        require(msg.sender == address(this), "not-self");
        _;
    }

    modifier onlySelfOrSafe() {
        require(msg.sender == address(this) || msg.sender == safe, "not-self-safe");
        _;
    }

    modifier onlyGuardian() {
        require(_guardians.contains(msg.sender), "not-guardian");
        _;
    }

    modifier onlyEntryPoint() {
        require(msg.sender == address(_entryPoint), "not-ep");
        _;
    }

    /// @notice Returns the configured ERC-4337 EntryPoint.
    function entryPoint() external view returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice Rotates account ownership to a new validator/config pair.
    /// @dev Must be executed through `execute(address(this), ...)` with a valid owner authorization payload.
    /// This path also cancels any in-flight recovery so stale guardian approvals cannot switch the account later.
    function rotateOwner(address newOwnerValidator, bytes calldata newOwnerConfig) external onlySelf {
        _setOwnerConfig(newOwnerValidator, newOwnerConfig);
        _resetRecovery(true);
    }

    /// @notice Adds a guardian that may participate in threshold recovery.
    /// @dev Changing the guardian set invalidates any active recovery request.
    function addGuardian(address guardian) external onlySelf {
        require(guardian != address(0), "guardian0");
        _guardians.add(guardian);
        _resetRecovery(true);
        emit GuardianAdded(guardian);
    }

    /// @notice Removes a guardian from the recovery set.
    /// @dev Changing the guardian set invalidates any active recovery request.
    function removeGuardian(address guardian) external onlySelf {
        _guardians.remove(guardian);
        _resetRecovery(true);
        emit GuardianRemoved(guardian);
    }

    /// @notice Sets the number of guardian approvals required for recovery acceptance.
    /// @dev The minimum threshold is `2` so a single compromised guardian cannot take over the account.
    function setGuardianThreshold(uint256 threshold) external onlySelf {
        require(threshold >= 2, "threshold<2");
        recoveryThreshold = threshold;
        _resetRecovery(true);
        emit GuardianThresholdUpdated(threshold);
    }

    /// @notice Starts a guardian recovery flow toward a new validator/config commitment.
    /// @dev The proposer automatically counts as the first approval. Recovery is blocked unless the
    /// current guardian set is large enough to satisfy the configured threshold.
    function proposeRecovery(address newOwnerValidator, bytes32 newOwnerConfigHash) external onlyGuardian {
        require(newOwnerValidator != address(0), "validator0");
        require(newOwnerConfigHash != bytes32(0), "config0");
        require(!recoveryRequest.active, "recovery-active");
        require(_guardians.length() >= recoveryThreshold, "guardians<threshold");

        uint256 nextNonce = recoveryNonce + 1;
        recoveryNonce = nextNonce;
        _recoveryApprovals[nextNonce][msg.sender] = true;
        recoveryRequest = RecoveryRequest({
            pendingOwnerValidator: newOwnerValidator,
            pendingOwnerConfigHash: newOwnerConfigHash,
            executeAfter: uint64(block.timestamp + RECOVERY_DELAY),
            approvals: 1,
            nonce: uint64(nextNonce),
            active: true
        });

        emit RecoveryProposed(msg.sender, newOwnerValidator, newOwnerConfigHash, block.timestamp + RECOVERY_DELAY, nextNonce);
        emit RecoveryApproved(msg.sender, newOwnerValidator, newOwnerConfigHash, 1, nextNonce);
    }

    /// @notice Adds a guardian approval to the currently active recovery request.
    /// @dev Guardians approve the exact `(validator, configHash)` pair stored in the request.
    function approveRecovery(address newOwnerValidator, bytes32 newOwnerConfigHash) external onlyGuardian {
        RecoveryRequest storage request = recoveryRequest;
        require(request.active, "recovery-inactive");
        require(request.pendingOwnerValidator == newOwnerValidator, "recovery-validator");
        require(request.pendingOwnerConfigHash == newOwnerConfigHash, "recovery-config");
        require(!_recoveryApprovals[request.nonce][msg.sender], "recovery-approved");

        _recoveryApprovals[request.nonce][msg.sender] = true;
        unchecked {
            ++request.approvals;
        }

        emit RecoveryApproved(msg.sender, newOwnerValidator, newOwnerConfigHash, request.approvals, request.nonce);
    }

    /// @notice Cancels the current recovery flow through an owner-authorized self-call.
    function cancelRecovery() external onlySelf {
        _resetRecovery(true);
    }

    /// @notice Allows the operational safe to cancel a recovery flow in an emergency.
    function cancelRecoveryBySafe() external onlySafe {
        _resetRecovery(true);
    }

    /// @notice Finalizes guardian recovery after enough approvals and the delay window have passed.
    /// @dev The caller supplies the full new owner config so the account can recompute and verify the
    /// committed hash before switching ownership.
    function acceptRecovery(address newOwnerValidator, bytes calldata newOwnerConfig) external {
        RecoveryRequest memory request = recoveryRequest;
        require(request.active, "recovery-inactive");
        require(request.pendingOwnerValidator == newOwnerValidator, "recovery-validator");
        require(uint256(request.approvals) >= recoveryThreshold, "recovery-threshold");
        require(block.timestamp >= uint256(request.executeAfter), "delay");
        require(IOwnerValidator(newOwnerValidator).configHash(newOwnerConfig) == request.pendingOwnerConfigHash, "recovery-config-hash");

        ownerValidator = newOwnerValidator;
        ownerConfigHash = request.pendingOwnerConfigHash;
        _resetRecovery(false);
        emit OwnerConfigUpdated(newOwnerValidator, ownerConfigHash);
    }

    /// @notice Grants or refreshes a session key for low-risk first-party actions.
    /// @dev A session grant by itself is not enough to execute calls. The key must also be configured
    /// with allowed targets/selectors, and every target must be safe-approved by the `safe` role.
    /// Re-granting the same key increments its version so stale allowlists from an older grant are ignored.
    function grantSessionKey(address key, SessionConfig calldata config) external onlySelf {
        require(key != address(0), "key0");
        require(config.callLimit > 0, "limit0");
        require(config.validUntil > block.timestamp, "expired");
        require(config.maxTotalValuePerUserOp >= config.maxValuePerCall, "value-range");
        if (config.allowBatch) {
            require(config.maxBatchCalls > 0, "batch0");
        }

        uint64 nextVersion = _sessionVersions[key] + 1;
        _sessionVersions[key] = nextVersion;
        sessionConfigs[key] = SessionConfig({
            validUntil: config.validUntil,
            callLimit: config.callLimit,
            usedCalls: 0,
            version: nextVersion,
            maxBatchCalls: config.allowBatch ? config.maxBatchCalls : 0,
            maxValuePerCall: config.maxValuePerCall,
            maxTotalValuePerUserOp: config.maxTotalValuePerUserOp,
            allowBatch: config.allowBatch
        });

        emit SessionKeyGranted(key, sessionConfigs[key]);
    }

    /// @notice Marks a target as callable by the current version of a given session key.
    /// @dev The target must still be `safe`-approved through `whitelistSessionTarget(...)` before
    /// session validation will allow execution.
    function setSessionTarget(address key, address target, bool allowed) external onlySelf {
        SessionConfig storage config = sessionConfigs[key];
        require(config.version != 0 && config.validUntil != 0, "session-missing");
        require(target != address(0), "target0");
        _sessionTargets[key][config.version][target] = allowed;
        emit SessionTargetSet(key, config.version, target, allowed);
    }

    /// @notice Marks a selector as callable for a specific target under the current session-key version.
    function setSessionSelector(address key, address target, bytes4 selector, bool allowed) external onlySelf {
        SessionConfig storage config = sessionConfigs[key];
        require(config.version != 0 && config.validUntil != 0, "session-missing");
        require(target != address(0), "target0");
        _sessionSelectors[key][config.version][target][selector] = allowed;
        emit SessionSelectorSet(key, config.version, target, selector, allowed);
    }

    /// @notice Adds or removes a target from the global session-safe allowlist managed by the operational safe.
    /// @dev Session execution requires both account-owner approval (`setSessionTarget`) and safe approval here.
    function whitelistSessionTarget(address target, bool allowed) external onlySafe {
        require(target != address(0), "target0");
        isSessionSafeTarget[target] = allowed;
        emit SessionSafeTargetSet(target, allowed);
    }

    /// @notice Revokes a session key immediately.
    function revokeSessionKey(address key) public onlySelf {
        _revokeSessionKey(key);
    }

    /// @notice Returns the current version number for a session key.
    /// @dev Versioning prevents stale target/selector grants from surviving a re-grant or revoke/recreate cycle.
    function sessionVersion(address key) external view returns (uint64) {
        return _sessionVersions[key];
    }

    /// @notice Returns whether the current session-key version is allowed to call the target.
    function isSessionTargetAllowed(address key, address target) external view returns (bool) {
        SessionConfig storage config = sessionConfigs[key];
        return _sessionTargets[key][config.version][target];
    }

    /// @notice Returns whether the current session-key version is allowed to call the selector on the target.
    function isSessionSelectorAllowed(address key, address target, bytes4 selector) external view returns (bool) {
        SessionConfig storage config = sessionConfigs[key];
        return _sessionSelectors[key][config.version][target][selector];
    }

    /// @notice Returns the number of currently configured guardians.
    function guardianCount() external view returns (uint256) {
        return _guardians.length();
    }

    /// @notice Returns whether the address is an active guardian.
    function isGuardian(address guardian) external view returns (bool) {
        return _guardians.contains(guardian);
    }

    /// @notice Allows the operational safe to approve delegatecall extensions for owner-scoped flows.
    /// @dev Session keys can never use `executeDelegate`, so this allowlist only affects owner-authorized operations.
    function whitelistImpl(address impl, bool allowed) external onlySafe {
        isWhitelistedImpl[impl] = allowed;
        emit ImplWhitelisted(impl, allowed);
    }

    /// @notice Pauses account execution and ETH reception.
    function pause() external onlySelfOrSafe {
        _pause();
    }

    /// @notice Resumes account execution and ETH reception.
    function unpause() external onlySelfOrSafe {
        _unpause();
    }

    /// @dev Recomputes and stores the validator-specific owner config hash for a new owner configuration.
    function _setOwnerConfig(address newOwnerValidator, bytes calldata newOwnerConfig) internal {
        require(newOwnerValidator != address(0), "validator0");
        require(newOwnerConfig.length > 0, "owner-config0");
        ownerValidator = newOwnerValidator;
        ownerConfigHash = IOwnerValidator(newOwnerValidator).configHash(newOwnerConfig);
        emit OwnerConfigUpdated(newOwnerValidator, ownerConfigHash);
    }

    /// @dev Revocation deletes only the current session config. Old allowlists remain versioned and unreachable.
    function _revokeSessionKey(address key) internal {
        uint64 version = sessionConfigs[key].version;
        delete sessionConfigs[key];
        emit SessionKeyRevoked(key, version);
    }

    /// @dev Recovery state is cleared whenever ownership, guardians, or thresholds change so stale approvals cannot be replayed.
    function _resetRecovery(bool emitCancellation) internal {
        RecoveryRequest memory request = recoveryRequest;
        if (request.active && emitCancellation) {
            emit RecoveryCancelled(request.nonce);
        }
        delete recoveryRequest;
    }

    /// @dev Splits an `execute*` call into its outer selector plus ABI-encoded payload for session validation.
    function _validationPayload(bytes calldata callData)
        internal
        pure
        returns (bytes4 outerSelector, bytes calldata payload)
    {
        require(callData.length >= 4, "cd<4");
        outerSelector = bytes4(callData);
        payload = callData[4:];
    }

    function _readSelector(bytes memory data) internal pure returns (bytes4 selector) {
        if (data.length < 4) return bytes4(0);
        assembly {
            selector := mload(add(data, 32))
        }
    }

    /// @dev Validates a single `execute(...)` call against the current session policy.
    function _validateExecute(
        SessionConfig storage config,
        address signer,
        bytes calldata payload
    ) internal view returns (bool) {
        (address target, uint256 value, bytes memory data) = abi.decode(payload, (address, uint256, bytes));
        return _validateInnerCall(config, signer, target, value, data);
    }

    /// @dev Validates a batched call against per-call limits and a per-userOp aggregate value limit.
    function _validateExecuteBatch(
        SessionConfig storage config,
        address signer,
        bytes calldata payload
    ) internal view returns (bool) {
        if (!config.allowBatch) return false;

        (address[] memory targets, uint256[] memory values, bytes[] memory data) =
            abi.decode(payload, (address[], uint256[], bytes[]));
        uint256 len = targets.length;
        if (len != values.length || len != data.length) return false;
        if (len > uint256(config.maxBatchCalls)) return false;

        uint256 totalValue;
        for (uint256 i; i < len; ++i) {
            if (!_validateInnerCall(config, signer, targets[i], values[i], data[i])) {
                return false;
            }
            totalValue += values[i];
            if (totalValue > uint256(config.maxTotalValuePerUserOp)) {
                return false;
            }
        }
        return true;
    }

    /// @dev Session execution is only allowed when all of these are true:
    /// the owner granted the target, the safe marked it as globally session-safe, the selector is allowlisted,
    /// and the per-call value cap is respected.
    function _validateInnerCall(
        SessionConfig storage config,
        address signer,
        address target,
        uint256 value,
        bytes memory data
    ) internal view returns (bool) {
        if (!_sessionTargets[signer][config.version][target]) return false;
        if (!isSessionSafeTarget[target]) return false;
        if (value > uint256(config.maxValuePerCall)) return false;
        if (data.length < 4) return false;

        bytes4 innerSelector = _readSelector(data);
        return _sessionSelectors[signer][config.version][target][innerSelector];
    }

    function _recoverSessionSigner(bytes32 userOpHash, bytes memory sessionSignature) internal pure returns (address) {
        return ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(userOpHash), sessionSignature);
    }

    /// @dev Validates either an owner payload or a session-key payload and returns EntryPoint-style validation data.
    /// Session-key validation mutates usage counters because call limits are enforced during validation itself.
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal returns (uint256 validationData) {
        (uint8 sigType, bytes memory sigPayload) = abi.decode(userOp.signature, (uint8, bytes));

        if (sigType == SIG_TYPE_OWNER) {
            bool validOwnerSig =
                IOwnerValidator(ownerValidator).validateUserOpSignature(address(this), ownerConfigHash, userOpHash, sigPayload);
            return validOwnerSig ? 0 : SIG_VALIDATION_FAILED;
        }

        if (sigType != SIG_TYPE_SESSION) {
            return SIG_VALIDATION_FAILED;
        }

        address signer = _recoverSessionSigner(userOpHash, sigPayload);
        SessionConfig storage config = sessionConfigs[signer];
        if (config.validUntil < block.timestamp || config.usedCalls >= config.callLimit) {
            return SIG_VALIDATION_FAILED;
        }

        (bytes4 outerSelector, bytes calldata payload) = _validationPayload(userOp.callData);

        bool allowed;
        if (outerSelector == this.execute.selector) {
            allowed = _validateExecute(config, signer, payload);
        } else if (outerSelector == this.executeBatch.selector) {
            allowed = _validateExecuteBatch(config, signer, payload);
        } else {
            return SIG_VALIDATION_FAILED;
        }

        if (!allowed) {
            return SIG_VALIDATION_FAILED;
        }

        unchecked {
            ++config.usedCalls;
        }
        uint64 validUntil = config.validUntil;
        if (config.usedCalls >= config.callLimit) {
            _revokeSessionKey(signer);
        }

        return uint256(validUntil) << 160;
    }

    /// @notice EntryPoint hook used to validate owner or session-key authorization for a user operation.
    /// @dev This function may top up missing account funds to the EntryPoint deposit after validation succeeds.
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external returns (uint256 validationData) {
        require(msg.sender == address(_entryPoint), "only entrypoint");

        validationData = _validateSignature(userOp, userOpHash);

        if (missingAccountFunds > 0) {
            (bool ok,) = address(_entryPoint).call{value: missingAccountFunds}("");
            require(ok, "deposit fail");
        }
    }

    /// @notice Executes a single call from the account.
    /// @dev Only the EntryPoint may call this function. Owner-auth and session-auth decisions are made earlier
    /// in `validateUserOp`, not at raw call time.
    function execute(address to, uint256 value, bytes calldata data)
        external
        onlyEntryPoint
        whenNotPaused
        nonReentrant
    {
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice Executes a batch of calls from the account.
    /// @dev Session keys can only use this path when their config explicitly enables batching and every
    /// inner call satisfies the target/selector/value limits checked during validation.
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

    /// @notice Executes an allowlisted delegatecall extension.
    /// @dev Session keys are never allowed to reach this function. It remains reserved for owner-authorized
    /// extension flows such as upgrades, modules, or controlled admin-style internal operations.
    function executeDelegate(address impl, bytes calldata data)
        external
        onlyEntryPoint
        whenNotPaused
        nonReentrant
    {
        require(isWhitelistedImpl[impl], "impl-not-allowed");
        (bool ok, bytes memory ret) = impl.delegatecall(data);
        if (!ok) assembly { revert(add(ret, 32), mload(ret)) }
    }

    /// @dev UUPS authorization is restricted to self-calls or the operational safe.
    function _authorizeUpgrade(address) internal override onlySelfOrSafe onlyProxy {}

    /// @notice ERC-1271 compatibility hook backed by the current owner validator.
    /// @dev This allows off-chain systems to treat the account like a signature-validating smart wallet
    /// without knowing the validator-specific owner config format.
    function isValidSignature(bytes32 hash, bytes memory signature) public view returns (bytes4) {
        return IOwnerValidator(ownerValidator).isValidSignature(address(this), ownerConfigHash, hash, signature)
            ? bytes4(0x1626ba7e)
            : bytes4(0xffffffff);
    }

    /// @notice Accepts ETH while the account is not paused.
    receive() external payable {
        require(!paused(), "paused");
    }
}

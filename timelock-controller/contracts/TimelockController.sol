// SPDX-License-Identifier: Apache-2.0
// OpenZeppelin Contracts (last updated v5.3.0) (governance/TimelockController.sol)

pragma solidity ^0.8.20;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC721HolderUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC721/utils/ERC721HolderUpgradeable.sol";
import {ERC1155HolderUpgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC1155/utils/ERC1155HolderUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @dev Contract module which acts as a timelocked controller. When set as the
 * owner of an `Ownable` smart contract, it enforces a timelock on all
 * `onlyOwner` maintenance operations. This gives time for users of the
 * controlled contract to exit before a potentially dangerous maintenance
 * operation is applied.
 *
 * By default, this contract is self administered, meaning administration tasks
 * have to go through the timelock process. The proposer (resp executor) role
 * is in charge of proposing (resp executing) operations. A common use case is
 * to position this {TimelockController} as the owner of a smart contract, with
 * a multisig or a DAO as the sole proposer.
 */
contract TimelockControllerUpgradeable is Initializable, AccessControlUpgradeable, ERC721HolderUpgradeable, ERC1155HolderUpgradeable {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);

    /// @custom:storage-location erc7201:openzeppelin.storage.TimelockController
    struct TimelockControllerStorage {
        mapping(bytes32 id => uint256) _timestamps;
        uint256 _minDelay;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.TimelockController")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant TimelockControllerStorageLocation = 0x9a37c2aa9d186a0969ff8a8267bf4e07e864c2f2768f5040949e28a624fb3600;

    function _getTimelockControllerStorage() private pure returns (TimelockControllerStorage storage $) {
        assembly {
            $.slot := TimelockControllerStorageLocation
        }
    }

    enum OperationState {
        Unset,
        Waiting,
        Ready,
        Done
    }

    /// @dev Mismatch between the parameter lengths for an operation call.
    error TimelockInvalidOperationLength(uint256 targets, uint256 payloads, uint256 values);

    /// @dev The scheduled operation does not meet the minimum delay.
    error TimelockInsufficientDelay(uint256 delay, uint256 minDelay);

    /// @dev The current state of an operation is not as required.
    /// `expectedStates` is a bitmap with enabled bits for each `OperationState` position; see `_encodeStateBitmap`.
    error TimelockUnexpectedOperationState(bytes32 operationId, bytes32 expectedStates);

    /// @dev The predecessor to an operation is not yet done.
    error TimelockUnexecutedPredecessor(bytes32 predecessorId);

    /// @dev The caller account is not authorized.
    error TimelockUnauthorizedCaller(address caller);

    /// @dev Emitted when a call is scheduled as part of operation `id`.
    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        uint256 delay
    );

    /// @dev Emitted when a call is performed as part of operation `id`.
    event CallExecuted(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data);

    /// @dev Emitted when a new proposal is scheduled with a non-zero salt.
    event CallSalt(bytes32 indexed id, bytes32 salt);

    /// @dev Emitted when operation `id` is cancelled.
    event Cancelled(bytes32 indexed id);

    /// @dev Emitted when the minimum delay for future operations is modified.
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    constructor() { _disableInitializers(); }

    function initialize(uint256 minDelay, address[] memory proposers, address[] memory executors, address admin) public virtual initializer {
        __TimelockController_init(minDelay, proposers, executors, admin);
    }
    /// @dev Initialize the timelock with a minimum delay, proposer set, executor set, and optional admin.
    /// The optional admin helps with initial configuration but should be renounced in favor of timelocked administration.
    function __TimelockController_init(uint256 minDelay, address[] memory proposers, address[] memory executors, address admin) internal onlyInitializing {
        __TimelockController_init_unchained(minDelay, proposers, executors, admin);
    }

    function __TimelockController_init_unchained(uint256 minDelay, address[] memory proposers, address[] memory executors, address admin) internal onlyInitializing {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        // self administration
        _grantRole(DEFAULT_ADMIN_ROLE, address(this));

        // optional admin
        if (admin != address(0)) {
            _grantRole(DEFAULT_ADMIN_ROLE, admin);
        }

        // register proposers and cancellers
        for (uint256 i = 0; i < proposers.length; ++i) {
            _grantRole(PROPOSER_ROLE, proposers[i]);
            _grantRole(CANCELLER_ROLE, proposers[i]);
        }

        // register executors
        for (uint256 i = 0; i < executors.length; ++i) {
            _grantRole(EXECUTOR_ROLE, executors[i]);
        }

        $._minDelay = minDelay;
        emit MinDelayChange(0, minDelay);
    }

    /// @dev Make a function callable only by a certain role, unless that role is granted to `address(0)` for open access.
    modifier onlyRoleOrOpenRole(bytes32 role) {
        if (!hasRole(role, address(0))) {
            _checkRole(role, _msgSender());
        }
        _;
    }

    /// @dev Allow the timelock to receive and hold ETH as part of scheduled maintenance flows.
    receive() external payable virtual {}

    /// @dev See {IERC165-supportsInterface}.
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControlUpgradeable, ERC1155HolderUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @dev Return whether an id corresponds to a registered operation, including Waiting, Ready, and Done states.
    function isOperation(bytes32 id) public view returns (bool) {
        return getOperationState(id) != OperationState.Unset;
    }

    /// @dev Return whether an operation is pending. A ready operation is also considered pending.
    function isOperationPending(bytes32 id) public view returns (bool) {
        OperationState state = getOperationState(id);
        return state == OperationState.Waiting || state == OperationState.Ready;
    }

    /// @dev Return whether an operation is ready for execution. A ready operation is also pending.
    function isOperationReady(bytes32 id) public view returns (bool) {
        return getOperationState(id) == OperationState.Ready;
    }

    /// @dev Return whether an operation is done.
    function isOperationDone(bytes32 id) public view returns (bool) {
        return getOperationState(id) == OperationState.Done;
    }

    /// @dev Return the timestamp at which an operation becomes ready: `0` for unset operations and `1` for done operations.
    function getTimestamp(bytes32 id) public view virtual returns (uint256) {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        return $._timestamps[id];
    }

    /// @dev Return the current operation state.
    function getOperationState(bytes32 id) public view virtual returns (OperationState) {
        uint256 timestamp = getTimestamp(id);
        if (timestamp == 0) {
            return OperationState.Unset;
        } else if (timestamp == _DONE_TIMESTAMP) {
            return OperationState.Done;
        } else if (timestamp > block.timestamp) {
            return OperationState.Waiting;
        } else {
            return OperationState.Ready;
        }
    }

    /// @dev Return the minimum delay in seconds for an operation to become valid.
    /// This value can be changed only through a scheduled `updateDelay` call.
    function getMinDelay() public view virtual returns (uint256) {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        return $._minDelay;
    }

    /// @dev Return the identifier of an operation containing a single transaction.
    function hashOperation(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt
    ) public pure virtual returns (bytes32) {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    /// @dev Return the identifier of an operation containing a batch of transactions.
    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) public pure virtual returns (bytes32) {
        return keccak256(abi.encode(targets, values, payloads, predecessor, salt));
    }

    /// @dev Schedule an operation containing a single transaction.
    /// Emits `CallSalt` when `salt` is non-zero and always emits `CallScheduled`.
    /// Requires the caller to hold PROPOSER_ROLE.
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual onlyRole(PROPOSER_ROLE) {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        _schedule(id, delay);
        emit CallScheduled(id, 0, target, value, data, predecessor, delay);
        if (salt != bytes32(0)) {
            emit CallSalt(id, salt);
        }
    }

    /// @dev Schedule an operation containing a batch of transactions.
    /// Emits `CallSalt` when `salt` is non-zero and emits one `CallScheduled` event per batch item.
    /// Requires the caller to hold PROPOSER_ROLE.
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual onlyRole(PROPOSER_ROLE) {
        if (targets.length != values.length || targets.length != payloads.length) {
            revert TimelockInvalidOperationLength(targets.length, payloads.length, values.length);
        }

        bytes32 id = hashOperationBatch(targets, values, payloads, predecessor, salt);
        _schedule(id, delay);
        for (uint256 i = 0; i < targets.length; ++i) {
            emit CallScheduled(id, i, targets[i], values[i], payloads[i], predecessor, delay);
        }
        if (salt != bytes32(0)) {
            emit CallSalt(id, salt);
        }
    }

    /// @dev Schedule an operation that becomes valid after a given delay.
    function _schedule(bytes32 id, uint256 delay) private {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        if (isOperation(id)) {
            revert TimelockUnexpectedOperationState(id, _encodeStateBitmap(OperationState.Unset));
        }
        uint256 minDelay = getMinDelay();
        if (delay < minDelay) {
            revert TimelockInsufficientDelay(delay, minDelay);
        }
        $._timestamps[id] = block.timestamp + delay;
    }

    /// @dev Cancel an operation.
    /// Requires the caller to hold CANCELLER_ROLE.
    function cancel(bytes32 id) public virtual onlyRole(CANCELLER_ROLE) {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        if (!isOperationPending(id)) {
            revert TimelockUnexpectedOperationState(
                id,
                _encodeStateBitmap(OperationState.Waiting) | _encodeStateBitmap(OperationState.Ready)
            );
        }
        delete $._timestamps[id];

        emit Cancelled(id);
    }

    /// @dev Execute a ready operation containing a single transaction.
    /// Emits `CallExecuted` and requires the caller to hold EXECUTOR_ROLE or for the executor role to be open.
    // This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    // thus any modifications to the operation during reentrancy should be caught.
    // slither-disable-next-line reentrancy-eth
    function execute(
        address target,
        uint256 value,
        bytes calldata payload,
        bytes32 predecessor,
        bytes32 salt
    ) public payable virtual onlyRoleOrOpenRole(EXECUTOR_ROLE) {
        bytes32 id = hashOperation(target, value, payload, predecessor, salt);

        _beforeCall(id, predecessor);
        _execute(target, value, payload);
        emit CallExecuted(id, 0, target, value, payload);
        _afterCall(id);
    }

    /// @dev Execute a ready operation containing a batch of transactions.
    /// Emits one `CallExecuted` event per transaction and requires the caller to hold EXECUTOR_ROLE or for the executor role to be open.
    // This function can reenter, but it doesn't pose a risk because _afterCall checks that the proposal is pending,
    // thus any modifications to the operation during reentrancy should be caught.
    // slither-disable-next-line reentrancy-eth
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) public payable virtual onlyRoleOrOpenRole(EXECUTOR_ROLE) {
        if (targets.length != values.length || targets.length != payloads.length) {
            revert TimelockInvalidOperationLength(targets.length, payloads.length, values.length);
        }

        bytes32 id = hashOperationBatch(targets, values, payloads, predecessor, salt);

        _beforeCall(id, predecessor);
        for (uint256 i = 0; i < targets.length; ++i) {
            address target = targets[i];
            uint256 value = values[i];
            bytes calldata payload = payloads[i];
            _execute(target, value, payload);
            emit CallExecuted(id, i, target, value, payload);
        }
        _afterCall(id);
    }

    /// @dev Execute a single scheduled call.
    function _execute(address target, uint256 value, bytes calldata data) internal virtual {
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        Address.verifyCallResult(success, returndata);
    }

    /// @dev Run pre-execution checks for an operation.
    function _beforeCall(bytes32 id, bytes32 predecessor) private view {
        if (!isOperationReady(id)) {
            revert TimelockUnexpectedOperationState(id, _encodeStateBitmap(OperationState.Ready));
        }
        if (predecessor != bytes32(0) && !isOperationDone(predecessor)) {
            revert TimelockUnexecutedPredecessor(predecessor);
        }
    }

    /// @dev Run post-execution checks for an operation and mark it as done.
    function _afterCall(bytes32 id) private {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        if (!isOperationReady(id)) {
            revert TimelockUnexpectedOperationState(id, _encodeStateBitmap(OperationState.Ready));
        }
        $._timestamps[id] = _DONE_TIMESTAMP;
    }

    /// @dev Change the minimum timelock duration for future operations.
    /// Emits `MinDelayChange`.
    /// The caller must be the timelock itself, which means this function can only be reached through a scheduled self-call.
    function updateDelay(uint256 newDelay) external virtual {
        TimelockControllerStorage storage $ = _getTimelockControllerStorage();
        address sender = _msgSender();
        if (sender != address(this)) {
            revert TimelockUnauthorizedCaller(sender);
        }
        emit MinDelayChange($._minDelay, newDelay);
        $._minDelay = newDelay;
    }

    /// @dev Encode an `OperationState` into a `bytes32` bitmap with the enum position bit enabled.
    function _encodeStateBitmap(OperationState operationState) internal pure returns (bytes32) {
        return bytes32(1 << uint8(operationState));
    }
}

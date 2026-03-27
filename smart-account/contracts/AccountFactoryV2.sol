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

import "@openzeppelin/contracts/proxy/Clones.sol";

import "./SmartAccountV2.sol";
import {IOwnerValidator} from "./interfaces/IOwnerValidator.sol";

/**
 * @title AccountFactory
 *
 * @notice
 * Deterministic factory for passkey-validator based smart accounts.
 * New accounts are keyed by `(ownerValidator, ownerConfigHash, salt)`.
 */
contract AccountFactoryV2 {
    /// @notice SmartAccount implementation cloned for new accounts.
    address public immutable implementation;
    /// @notice Shared EntryPoint passed into every new SmartAccount clone.
    address public immutable entryPoint;
    /// @notice Operational safe copied into every new SmartAccount clone.
    address public immutable safe;

    event AccountCreated(address indexed account, address indexed ownerValidator, bytes32 indexed ownerConfigHash, uint256 salt);

    constructor(address _impl, address _entryPoint, address _safe) {
        require(_impl.code.length > 0, "impl-0");
        implementation = _impl;
        entryPoint = _entryPoint;
        safe = _safe;
    }

    /// @dev Internal deterministic key used both for replay protection and CREATE2-style address prediction.
    function _key(address ownerValidator, bytes32 ownerConfigHash, uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(ownerValidator, ownerConfigHash, salt));
    }

    /// @notice Creates a new deterministic SmartAccount clone for the provided validator-backed owner config.
    /// @dev Accounts are unique per `(ownerValidator, ownerConfigHash, salt)`. Reusing the same tuple reverts.
    /// The owner config itself stays opaque to the factory; only the validator decides how it is hashed.
    /// @param ownerValidator Validator contract that will prove owner-scoped operations for the new account.
    /// @param ownerConfig Validator-specific owner config bytes used to derive the stored config hash.
    /// @param salt Application-defined salt for deterministic account addressing.
    /// @return account Newly deployed SmartAccount clone address.
    function createAccount(address ownerValidator, bytes calldata ownerConfig, uint256 salt) external returns (address account) {
        require(ownerValidator != address(0), "validator0");
        bytes32 ownerConfigHash = IOwnerValidator(ownerValidator).configHash(ownerConfig);
        bytes32 key = _key(ownerValidator, ownerConfigHash, salt);
        account = Clones.predictDeterministicAddress(implementation, key, address(this));
        require(account.code.length == 0, "salt-used");

        account = Clones.cloneDeterministic(implementation, key);

        SmartAccountV2(payable(account)).initialize(ownerValidator, ownerConfig, entryPoint, safe);
        emit AccountCreated(account, ownerValidator, ownerConfigHash, salt);
    }

    /// @notice Predicts the deterministic address that `createAccount` would deploy for the same inputs.
    /// @dev This must stay aligned with `_key(...)` and the current implementation clone salt logic.
    function predictAddress(address ownerValidator, bytes calldata ownerConfig, uint256 salt) external view returns (address) {
        bytes32 ownerConfigHash = IOwnerValidator(ownerValidator).configHash(ownerConfig);
        bytes32 key = _key(ownerValidator, ownerConfigHash, salt);
        return Clones.predictDeterministicAddress(implementation, key, address(this));
    }
}

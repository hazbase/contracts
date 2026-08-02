// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MockERC1271Authorizer is IERC1271 {
    using ECDSA for bytes32;

    bytes4 private constant MAGIC_VALUE = IERC1271.isValidSignature.selector;
    address public immutable signer;

    constructor(address signer_) {
        signer = signer_;
    }

    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4) {
        return hash.recover(signature) == signer ? MAGIC_VALUE : bytes4(0xffffffff);
    }
}

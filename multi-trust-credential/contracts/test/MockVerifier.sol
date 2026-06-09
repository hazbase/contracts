// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockVerifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external pure returns (bool) {
        return true;
    }
}

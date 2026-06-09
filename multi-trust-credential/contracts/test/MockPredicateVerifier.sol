// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockPredicateVerifier {
    bool public result = true;

    function setResult(bool nextResult) external {
        result = nextResult;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[6] calldata
    ) external view returns (bool) {
        return result;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external view returns (bool) {
        return result;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[9] calldata
    ) external view returns (bool) {
        return result;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[10] calldata
    ) external view returns (bool) {
        return result;
    }
}

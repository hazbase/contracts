// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

contract MockBondToken {
    mapping(address => mapping(address => bool)) private _approvals;
    mapping(uint256 => mapping(uint256 => mapping(address => uint256))) private _balances;

    function mint(address to, uint256 classId, uint256 nonceId, uint256 amount) external {
        _balances[classId][nonceId][to] += amount;
    }

    function setApprovalForAll(address operator, bool approved) external {
        _approvals[msg.sender][operator] = approved;
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _approvals[owner][operator];
    }

    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external {
        require(msg.sender == from || _approvals[from][msg.sender], 'NOT_OPERATOR');
        uint256 bal = _balances[classId][nonceId][from];
        require(bal >= amount, 'INSUFF_BAL');
        unchecked {
            _balances[classId][nonceId][from] = bal - amount;
        }
        _balances[classId][nonceId][to] += amount;
    }

    function balanceOf(address owner, uint256 classId, uint256 nonceId) external view returns (uint256) {
        return _balances[classId][nonceId][owner];
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}

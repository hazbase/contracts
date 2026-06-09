// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

/// @dev Same two signatures as AgreementManager's `IERC1400`, so `type(IERC1400Min).interfaceId`
/// equals the id AgreementManager probes via `safeSupportsInterface`.
interface IERC1400Min {
    function transferByPartition(bytes32 partition, address to, uint256 value, bytes calldata data) external;
    function balanceOfByPartition(bytes32 partition, address tokenHolder) external view returns (uint256);
}

/// @title MockERC1400
/// @notice Minimal partitioned token used to test AgreementManager's ERC-1400 escrow/settlement.
/// Escrow must PULL the issuer's tokens via the operator-scoped transfer; settlement sends the
/// contract's own (escrowed) balance via the msg.sender-scoped transfer.
contract MockERC1400 is IERC165, IERC1400Min {
    mapping(bytes32 => mapping(address => uint256)) private _balances;
    mapping(address => mapping(address => bool))   public isOperator; // holder => operator => approved

    function mint(bytes32 partition, address to, uint256 amount) external {
        _balances[partition][to] += amount;
    }

    function authorizeOperator(address operator) external {
        isOperator[msg.sender][operator] = true;
    }

    function balanceOfByPartition(bytes32 partition, address holder) external view override returns (uint256) {
        return _balances[partition][holder];
    }

    /// @notice msg.sender-scoped transfer — used by AgreementManager settlement (contract -> recipient).
    function transferByPartition(bytes32 partition, address to, uint256 value, bytes calldata) external override {
        require(_balances[partition][msg.sender] >= value, "insufficient");
        _balances[partition][msg.sender] -= value;
        _balances[partition][to] += value;
    }

    /// @notice Operator-scoped transfer — used by AgreementManager escrow (issuer -> contract). The
    /// caller must be an authorized operator of `from` (or `from` itself).
    function operatorTransferByPartition(
        bytes32 partition,
        address from,
        address to,
        uint256 value,
        bytes calldata,
        bytes calldata
    ) external {
        require(from == msg.sender || isOperator[from][msg.sender], "not operator");
        require(_balances[partition][from] >= value, "insufficient");
        _balances[partition][from] -= value;
        _balances[partition][to] += value;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return interfaceId == type(IERC1400Min).interfaceId || interfaceId == type(IERC165).interfaceId;
    }
}

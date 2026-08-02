// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

/**
 * @title PooledTokenEscrow
 * @notice Asset-agnostic ERC-20 escrow for many-to-one pooled payments.
 *
 * A creator opens an escrow for one ERC-20 token. Any number of contributors
 * can fund it while it is open. The beneficiary can be fixed at creation or
 * assigned later using an EIP-712 authorization from the escrow's immutable
 * authorizer. The beneficiary claims the complete pool, or contributors pull
 * their own refunds after cancellation or expiry.
 *
 * Product metadata, recipient hints, visibility, moderation, notifications,
 * and identity verification deliberately remain off-chain. A `metadataHash`
 * may bind an escrow to immutable off-chain terms without exposing them here.
 *
 * Security properties:
 * - neither the creator nor any privileged role can withdraw escrowed funds;
 * - refunds are pulled by contributors, never redistributed by an operator;
 * - beneficiary authorizations are domain-separated by chain and contract;
 * - actual received balances are measured for fee-on-transfer ERC-20 tokens;
 * - native currency, rebasing tokens, and direct token transfers are unsupported.
 */
contract PooledTokenEscrow is
    AccessControlEnumerableUpgradeable,
    EIP712Upgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    bytes32 public constant BENEFICIARY_ASSIGNMENT_TYPEHASH = keccak256(
        "BeneficiaryAssignment(bytes32 escrowId,address beneficiary,uint256 nonce,uint256 deadline)"
    );

    enum EscrowStatus {
        None,
        Open,
        Released,
        Refundable,
        Closed
    }

    struct Escrow {
        address token;
        address creator;
        address beneficiary;
        address authorizer;
        uint64 expiresAt;
        EscrowStatus status;
        uint256 beneficiaryNonce;
        uint256 totalDeposited;
        uint256 totalReleased;
        uint256 totalRefunded;
        bytes32 metadataHash;
    }

    mapping(bytes32 escrowId => Escrow escrow) private _escrows;
    mapping(bytes32 escrowId => mapping(address contributor => uint256 amount)) private _contributions;
    mapping(bytes32 escrowId => mapping(address contributor => uint256 amount)) private _refunds;
    mapping(bytes32 escrowId => mapping(bytes32 contributionId => bool used)) private _usedContributionIds;
    mapping(bytes32 escrowId => mapping(bytes32 contributionId => uint256 amount)) private _contributionAmounts;
    mapping(address token => uint256 amount) private _lockedByToken;

    event EscrowCreated(
        bytes32 indexed escrowId,
        address indexed token,
        address indexed creator,
        address beneficiary,
        address authorizer,
        uint64 expiresAt,
        bytes32 metadataHash
    );
    event ContributionDeposited(
        bytes32 indexed escrowId,
        bytes32 indexed contributionId,
        address indexed contributor,
        uint256 requestedAmount,
        uint256 receivedAmount
    );
    event BeneficiaryAssigned(
        bytes32 indexed escrowId,
        address indexed beneficiary,
        address indexed authorizer,
        uint256 nonce
    );
    event EscrowReleased(bytes32 indexed escrowId, address indexed beneficiary, uint256 amount);
    event RefundsEnabled(bytes32 indexed escrowId, address indexed enabledBy, uint256 refundableAmount);
    event ContributionRefunded(bytes32 indexed escrowId, address indexed contributor, uint256 amount);
    event EscrowClosed(bytes32 indexed escrowId);

    error ZeroAddress();
    error InvalidEscrowId();
    error InvalidContributionId();
    error InvalidAmount();
    error InvalidExpiry();
    error InvalidBeneficiaryConfiguration();
    error EscrowAlreadyExists();
    error EscrowNotFound();
    error EscrowNotOpen();
    error EscrowExpired();
    error EscrowNotExpired();
    error ContributionAlreadyExists();
    error NoTokensReceived();
    error BeneficiaryAlreadyAssigned();
    error BeneficiaryNotAssigned();
    error InvalidAuthorizationNonce();
    error AuthorizationExpired();
    error InvalidAuthorization();
    error NotBeneficiary();
    error NotCreator();
    error NothingToClaim();
    error RefundsNotEnabled();
    error NothingToRefund();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControlEnumerable_init();
        __EIP712_init("PooledTokenEscrow", "1");
        __Pausable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(PAUSER_ROLE, admin);
    }

    function contractType() external pure returns (string memory) {
        return "PooledTokenEscrow";
    }

    function contractVersion() external pure returns (string memory) {
        return "1";
    }

    /**
     * @notice Create a new escrow.
     * @param escrowId Application-generated unique identifier.
     * @param token ERC-20 token held by this escrow.
     * @param beneficiary Fixed recipient, or zero when assigned later.
     * @param authorizer Signer allowed to authorize a later beneficiary. Must
     *        be zero when `beneficiary` is already fixed.
     * @param expiresAt Unix timestamp after which refunds can be enabled. Zero
     *        means no automatic expiry.
     * @param metadataHash Optional hash of immutable off-chain terms.
     */
    function createEscrow(
        bytes32 escrowId,
        address token,
        address beneficiary,
        address authorizer,
        uint64 expiresAt,
        bytes32 metadataHash
    ) external whenNotPaused {
        if (escrowId == bytes32(0)) revert InvalidEscrowId();
        if (token == address(0) || token.code.length == 0) revert ZeroAddress();
        if (_escrows[escrowId].status != EscrowStatus.None) revert EscrowAlreadyExists();
        if (expiresAt != 0 && expiresAt <= block.timestamp) revert InvalidExpiry();
        if (
            (beneficiary == address(0) && authorizer == address(0)) ||
            (beneficiary != address(0) && authorizer != address(0))
        ) revert InvalidBeneficiaryConfiguration();

        address creator = _msgSender();
        _escrows[escrowId] = Escrow({
            token: token,
            creator: creator,
            beneficiary: beneficiary,
            authorizer: authorizer,
            expiresAt: expiresAt,
            status: EscrowStatus.Open,
            beneficiaryNonce: 0,
            totalDeposited: 0,
            totalReleased: 0,
            totalRefunded: 0,
            metadataHash: metadataHash
        });

        emit EscrowCreated(
            escrowId,
            token,
            creator,
            beneficiary,
            authorizer,
            expiresAt,
            metadataHash
        );
    }

    /**
     * @notice Deposit ERC-20 tokens into an open escrow.
     * @dev `contributionId` makes retries idempotent at the application layer.
     *      The amount credited is the actual balance increase.
     */
    function deposit(bytes32 escrowId, bytes32 contributionId, uint256 amount)
        external
        whenNotPaused
        nonReentrant
        returns (uint256 receivedAmount)
    {
        Escrow storage escrow = _openEscrow(escrowId);
        _requireNotExpired(escrow);
        if (contributionId == bytes32(0)) revert InvalidContributionId();
        if (amount == 0) revert InvalidAmount();
        if (_usedContributionIds[escrowId][contributionId]) revert ContributionAlreadyExists();

        _usedContributionIds[escrowId][contributionId] = true;
        IERC20 token = IERC20(escrow.token);
        uint256 beforeBalance = token.balanceOf(address(this));
        token.safeTransferFrom(_msgSender(), address(this), amount);
        uint256 afterBalance = token.balanceOf(address(this));
        if (afterBalance <= beforeBalance) revert NoTokensReceived();

        receivedAmount = afterBalance - beforeBalance;
        address contributor = _msgSender();
        _contributionAmounts[escrowId][contributionId] = receivedAmount;
        _contributions[escrowId][contributor] += receivedAmount;
        escrow.totalDeposited += receivedAmount;
        _lockedByToken[escrow.token] += receivedAmount;

        emit ContributionDeposited(
            escrowId,
            contributionId,
            contributor,
            amount,
            receivedAmount
        );
    }

    /**
     * @notice Assign a beneficiary using the escrow authorizer's EIP-712 signature.
     * @dev Anyone may submit the authorization; it can only assign once.
     */
    function assignBeneficiary(
        bytes32 escrowId,
        address beneficiary,
        uint256 nonce,
        uint256 deadline,
        bytes calldata authorization
    ) external whenNotPaused {
        Escrow storage escrow = _openEscrow(escrowId);
        _requireNotExpired(escrow);
        if (beneficiary == address(0)) revert ZeroAddress();
        if (escrow.beneficiary != address(0)) revert BeneficiaryAlreadyAssigned();
        if (nonce != escrow.beneficiaryNonce) revert InvalidAuthorizationNonce();
        if (deadline < block.timestamp) revert AuthorizationExpired();

        bytes32 digest = beneficiaryAssignmentDigest(escrowId, beneficiary, nonce, deadline);
        if (!SignatureChecker.isValidSignatureNow(escrow.authorizer, digest, authorization)) {
            revert InvalidAuthorization();
        }

        escrow.beneficiary = beneficiary;
        escrow.beneficiaryNonce = nonce + 1;
        emit BeneficiaryAssigned(escrowId, beneficiary, escrow.authorizer, nonce);
    }

    /** @notice Claim all funds in an open, non-expired escrow. */
    function claim(bytes32 escrowId) external whenNotPaused nonReentrant returns (uint256 amount) {
        Escrow storage escrow = _openEscrow(escrowId);
        _requireNotExpired(escrow);
        if (escrow.beneficiary == address(0)) revert BeneficiaryNotAssigned();
        if (_msgSender() != escrow.beneficiary) revert NotBeneficiary();

        amount = escrow.totalDeposited - escrow.totalRefunded;
        if (amount == 0) revert NothingToClaim();

        escrow.status = EscrowStatus.Released;
        escrow.totalReleased = amount;
        _lockedByToken[escrow.token] -= amount;
        IERC20(escrow.token).safeTransfer(escrow.beneficiary, amount);

        emit EscrowReleased(escrowId, escrow.beneficiary, amount);
        emit EscrowClosed(escrowId);
    }

    /**
     * @notice Cancel an open escrow and make every contribution refundable.
     * @dev Only the creator can cancel; funds are never sent to the creator.
     */
    function cancelEscrow(bytes32 escrowId) external whenNotPaused {
        Escrow storage escrow = _openEscrow(escrowId);
        if (_msgSender() != escrow.creator) revert NotCreator();
        _enableRefunds(escrowId, escrow);
    }

    /** @notice Permissionlessly enable refunds once a finite escrow expires. */
    function enableRefunds(bytes32 escrowId) external whenNotPaused {
        Escrow storage escrow = _openEscrow(escrowId);
        if (escrow.expiresAt == 0 || block.timestamp < escrow.expiresAt) revert EscrowNotExpired();
        _enableRefunds(escrowId, escrow);
    }

    /** @notice Withdraw the caller's entire refundable contribution. */
    function refund(bytes32 escrowId) external whenNotPaused nonReentrant returns (uint256 amount) {
        Escrow storage escrow = _escrow(escrowId);
        if (escrow.status != EscrowStatus.Refundable) revert RefundsNotEnabled();

        address contributor = _msgSender();
        amount = _contributions[escrowId][contributor] - _refunds[escrowId][contributor];
        if (amount == 0) revert NothingToRefund();

        _refunds[escrowId][contributor] += amount;
        escrow.totalRefunded += amount;
        _lockedByToken[escrow.token] -= amount;
        if (escrow.totalRefunded == escrow.totalDeposited) {
            escrow.status = EscrowStatus.Closed;
        }

        IERC20(escrow.token).safeTransfer(contributor, amount);
        emit ContributionRefunded(escrowId, contributor, amount);
        if (escrow.status == EscrowStatus.Closed) emit EscrowClosed(escrowId);
    }

    function getEscrow(bytes32 escrowId) external view returns (Escrow memory) {
        return _escrow(escrowId);
    }

    function contributionOf(bytes32 escrowId, address contributor) external view returns (uint256) {
        return _contributions[escrowId][contributor];
    }

    function refundedOf(bytes32 escrowId, address contributor) external view returns (uint256) {
        return _refunds[escrowId][contributor];
    }

    function refundableOf(bytes32 escrowId, address contributor) external view returns (uint256) {
        Escrow storage escrow = _escrows[escrowId];
        if (escrow.status != EscrowStatus.Refundable) return 0;
        return _contributions[escrowId][contributor] - _refunds[escrowId][contributor];
    }

    function contributionAmount(bytes32 escrowId, bytes32 contributionId) external view returns (uint256) {
        return _contributionAmounts[escrowId][contributionId];
    }

    function isContributionIdUsed(bytes32 escrowId, bytes32 contributionId) external view returns (bool) {
        return _usedContributionIds[escrowId][contributionId];
    }

    function lockedBalanceOf(address token) external view returns (uint256) {
        return _lockedByToken[token];
    }

    function beneficiaryAssignmentDigest(
        bytes32 escrowId,
        address beneficiary,
        uint256 nonce,
        uint256 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    BENEFICIARY_ASSIGNMENT_TYPEHASH,
                    escrowId,
                    beneficiary,
                    nonce,
                    deadline
                )
            )
        );
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _escrow(bytes32 escrowId) internal view returns (Escrow storage escrow) {
        escrow = _escrows[escrowId];
        if (escrow.status == EscrowStatus.None) revert EscrowNotFound();
    }

    function _openEscrow(bytes32 escrowId) internal view returns (Escrow storage escrow) {
        escrow = _escrow(escrowId);
        if (escrow.status != EscrowStatus.Open) revert EscrowNotOpen();
    }

    function _requireNotExpired(Escrow storage escrow) internal view {
        if (escrow.expiresAt != 0 && block.timestamp >= escrow.expiresAt) revert EscrowExpired();
    }

    function _enableRefunds(bytes32 escrowId, Escrow storage escrow) internal {
        if (escrow.totalDeposited == 0) {
            escrow.status = EscrowStatus.Closed;
            emit RefundsEnabled(escrowId, _msgSender(), 0);
            emit EscrowClosed(escrowId);
            return;
        }

        escrow.status = EscrowStatus.Refundable;
        emit RefundsEnabled(
            escrowId,
            _msgSender(),
            escrow.totalDeposited - escrow.totalRefunded
        );
    }

    uint256[41] private __gap;
}

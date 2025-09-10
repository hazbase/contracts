// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______    
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\   
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\   
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\ 
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/                                                                         
//
//    https://hazbase.com

import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol"; 
import "@openzeppelin/contracts-upgradeable/governance/utils/VotesUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ───── Whitelist registry (optional) ───── */
interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

/**
 * @title PrivilegeEdition
 *
 * @notice
 * - Purpose: Upgradable ERC-1155 collection for **privilege/reward editions** with:
 *   * Optional **soulbound** mode (non-transferable between EOAs),
 *   * **Royalty** support (ERC-2981),
 *   * **Lazy mint** via **EIP-712 vouchers**,
 *   * **Per-id supply caps** with lock,
 *   * **Expiry** (per-id) and sweeping helpers,
 *   * Optional **whitelist (KYC)** checks on transfers,
 *   * **Voting power** integration (VotesUpgradeable): voting units = `tier × amount`,
 *   * ERC-2771 meta-transactions and **UUPS** upgradeability.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Cap logic: `_enforceCap` ensures the cumulative minted amount ≤ `cap` once locked.
 * - Voucher: Nonces are tracked per signer; signature must be from a MINTER.
 * - Soulbound: enforced during `_update` for non-mint/non-burn transfers.
 * - Whitelist: `_enforceWL` runs after balance updates in `_update` (post-checks).
 * - Voting units: `_transferVotingUnits` is updated **after** core balance changes.
 * - Upgrade: `_authorizeUpgrade` is gated by ADMIN_ROLE. Meta-tx via ERC-2771 overrides.
 */

contract PrivilegeEdition is
    ERC1155Upgradeable,
    EIP712Upgradeable,
    ERC2981Upgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable,
    UUPSUpgradeable,
    VotesUpgradeable
{
    using ECDSA for bytes32;

    /*────────────────────────── Errors ─────────────────────────*/
    error NonceUsed();
    error InvalidSigner();
    error VoucherExpired();
    error SoulboundErr();
    error TransferRoleRequired();
    error LenMismatch();
    error NonExistentToken();
    error InvalidRecipient();
    error InsufficientBalance();
    error SameOwner();
    error Expired();
    error CapZero();
    error AlreadyLocked();
    error CapExceeded();
    error ZeroAmount();
    error NoExpired();
    error AlreadyMinted();

    /*────────────────────── Voucher (EIP-712) ──────────────────*/

    /**
     * @notice EIP-712 voucher for lazy minting.
     * @param id         Token id to mint.
     * @param amount     Amount to mint.
     * @param uri        Optional per-id metadata URI (overrides base).
     * @param tier       Voting tier factor for this id (0..255).
     * @param expiresAt  Unix time after which the edition is considered expired.
     * @param validUntil Unix time until when the voucher is valid.
     * @param nonce      Unique nonce per issuer to avoid replay.
     * @param issuer     Address that must hold MINTER_ROLE and sign the voucher.
     * @param to         Recipient (address(0) ⇒ msg.sender).
     */
    struct MintVoucher {
        uint256 id;
        uint256 amount;
        string  uri;
        uint8   tier;
        uint64  expiresAt;
        uint64  validUntil;
        uint256 nonce;
        address issuer;
        address to;
    }
    bytes32 private constant VOUCHER_TYPEHASH =
        keccak256("MintVoucher(uint256 id,uint256 amount,string uri,uint8 tier,uint64 expiresAt,uint64 validUntil,uint256 nonce,address issuer,address to)");

    /// @dev anti-replay: issuer => (nonce => used?)
    mapping(address => mapping(uint256 => bool)) private _nonceUsed;
    /// @dev optional nonce counter for off-chain use
    mapping(address => uint256) private _nonces;

    /// @notice Optional on-chain whitelist registry (if set, transfers require both ends whitelisted).
    IWhitelist public whitelist;

    /*────────────────────── Token metadata ─────────────────────*/

    /**
     * @dev Per-id edition info.
     * - `expiresAt`: after this timestamp the id is sweepable.
     * - `tier`: voting weight factor used by VotesUpgradeable.
     * - `uri`: optional per-id metadata URI.
     */
    struct EditionInfo { uint64 expiresAt; uint8 tier; string uri; }
    mapping(uint256 => EditionInfo) private _editions;

    /// @dev Supply accounting per id.
    mapping(uint256 => uint256) private _maxSupply; // 0 = unlocked
    mapping(uint256 => uint256) private _minted;
    mapping(uint256 => uint256) private _burned;

    /// @notice Arbitrary reward type per id (points, coupon, etc.).
    mapping(uint256 => uint256) private _rewardType;

    /// @dev Voting cache per holder (sum of tier × amount across ids).
    mapping(address => uint256) private _votesBalance;

    /// @notice When true, transfers between non-zero addresses revert.
    bool public soulbound;

    /*────────────────────────── Events ─────────────────────────*/

    /// @notice Emitted when a per-id URI/tier/expiry is changed (metadata may need refresh).
    event MetadataUpdate(uint256 indexed id);
    /// @notice Emitted when user redeems (burns) rewards of an id.
    event RewardRedeemed(address indexed user, uint256 indexed id, uint256 amount);

    /**
     * @notice Disable initializers for the implementation (UUPS pattern).
     */
    constructor() { _disableInitializers(); }

    /*──────────────────────── Initializer ─────────────────────*/

    /**
     * @notice Initialize the privilege edition collection.
     * @param baseURI         Base URI for ERC-1155.
     * @param admin           Admin address (granted roles via RolesCommon).
     * @param forwarders      Trusted ERC-2771 forwarders (meta-tx).
     * @param royaltyReceiver Default royalty receiver (ERC-2981).
     * @param royaltyFee      Royalty fee in basis points (0..10000).
     *
     * @dev Calls initializers for ERC1155, EIP712(name=PrivilegeEdition,version=1),
     *      ERC2981, Pausable, ReentrancyGuard, ERC2771, UUPS, RolesCommon, and Votes.
     *      Grants MINTER_ROLE to `admin`.
     */
    function initialize(
        string calldata baseURI,
        address admin,
        address[] calldata forwarders,
        address royaltyReceiver,
        uint96  royaltyFee
    ) external initializer {
        __ERC1155_init(baseURI);
        __EIP712_init("PrivilegeEdition", "1");
        __ERC2981_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __ERC2771Context_init(forwarders);
        __UUPSUpgradeable_init();
        __RolesCommon_init(admin);
        __Votes_init();

        _setDefaultRoyalty(royaltyReceiver, royaltyFee);
        _grantRole(MINTER_ROLE, admin);
    }

    /*──────────────────────── Introspection / Contract meta ───────────────────*/

    /**
     * @notice Contract type string (EIP-712 `name()`).
     * @return string The EIP-712 domain name.
     */
    function contractType() external view returns (string memory) {
        return _EIP712Name();
    }

    /**
     * @notice Contract version string (EIP-712 `version()`).
     * @return string The EIP-712 domain version.
     */
    function contractVersion() external view returns (string memory) {
        return _EIP712Version();
    }

    /**
     * @notice Return current base URI stored by ERC1155.
     * @return string The base URI.
     */
    function contractURI() public view returns (string memory) {
        ERC1155Storage storage $ = _getERC1155Storage();
        return $._uri;
    }

    /*──────────────────────── Royalty (ERC-2981) ─────────────────────────*/

    /**
     * @notice Set default royalty.
     * @param receiver Royalty receiver.
     * @param fee      Fee in basis points (0..10000).
     *
     * @dev Only ROYALTY_ROLE can call.
     */
    function setDefaultRoyalty(address receiver, uint96 fee) external onlyRole(ROYALTY_ROLE) {
        _setDefaultRoyalty(receiver, fee);
    }

    /**
     * @notice Delete default royalty.
     * @dev Only ROYALTY_ROLE can call.
     */
    function deleteDefaultRoyalty() external onlyRole(ROYALTY_ROLE) {
        _deleteDefaultRoyalty();
    }

    /*──────────────────────── Supply caps ─────────────────────────*/

    /**
     * @notice Lock maximum total supply for token id `id`.
     * @param id  Token id.
     * @param cap Maximum supply (>0). Cannot be changed once set.
     *
     * @custom:reverts CapZero        if cap == 0
     * @custom:reverts AlreadyLocked  if cap already set for id
     */
    function lockSupply(uint256 id, uint256 cap) external onlyRole(ADMIN_ROLE) {
        if (cap <= 0) revert CapZero();
        if (_maxSupply[id] != 0) revert AlreadyLocked();
        _maxSupply[id] = cap;
    }

    /**
     * @notice Internal cap enforcement helper (increments minted).
     * @param id  Token id.
     * @param amt Mint amount.
     * @custom:reverts CapExceeded if minted + amt > cap (when cap != 0)
     */
    function _enforceCap(uint256 id, uint256 amt) internal {
        uint256 cap = _maxSupply[id];
        uint256 minted = _minted[id];
        if (cap != 0) {
            if (minted + amt > cap) revert CapExceeded();
        }
        _minted[id] = minted + amt;
    }

    /**
     * @notice Total minted for id (including burned).
     */
    function totalMinted(uint256 id) external view returns (uint256) {
        return _minted[id];
    }

    /**
     * @notice Circulating supply for id (= minted − burned).
     */
    function totalSupply(uint256 id) public view returns (uint256) {
        unchecked {
            return _minted[id] - _burned[id];
        }
    }

    /**
     * @notice Read max supply cap for id (0 = unlocked/unlimited).
     */
    function maxSupply(uint256 id) external view returns (uint256) {
        return _maxSupply[id];
    }

    /**
     * @notice Set voting tier for an id before any mint has occurred.
     * @param id      Token id.
     * @param newTier Tier value (0..255).
     *
     * @custom:reverts AlreadyMinted if any amount has been minted for id
     */
    function setTier(uint256 id, uint8 newTier)
        external
        onlyRole(MINTER_ROLE)
    {
        if (_minted[id] != 0) revert AlreadyMinted();
        _editions[id].tier = newTier;
        emit MetadataUpdate(id);
    }

    /*──────────────────────── Minting ─────────────────────────*/

    /**
     * @notice Mint `amt` of `id` to `to` with metadata and reward type.
     * @param to    Recipient address.
     * @param id    Token id.
     * @param amt   Amount to mint.
     * @param uri_  Optional per-id URI (overrides base for this id).
     * @param tier  Voting tier for this id.
     * @param exp   Expiry timestamp (0 = never expires).
     * @param rType Arbitrary reward type code for this id.
     *
     * @dev Only MINTER_ROLE; respects cap; updates edition metadata and emits `MetadataUpdate`.
     */
    function mint(address to, uint256 id, uint256 amt, string calldata uri_, uint8 tier, uint64 exp, uint256 rType)
        external onlyRole(MINTER_ROLE) whenNotPaused
    {
        _enforceCap(id, amt);
        _rewardType[id] = rType;
        _editions[id] = EditionInfo({expiresAt: exp, tier: tier, uri: uri_});
        _mint(to, id, amt, "");
        emit MetadataUpdate(id);
    }

    /*──────────────────────── Lazy mint (Voucher) ─────────────────────────*/

    /**
     * @notice Redeem a signed EIP-712 voucher to mint tokens.
     * @param v     MintVoucher struct (see type definition).
     * @param sig   ECDSA signature by `v.issuer` over the voucher typed data.
     * @param rType Reward type to assign for `v.id`.
     *
     * @dev
     * - Checks `block.timestamp ≤ v.validUntil`.
     * - Enforces cap and anti-replay (`_nonceUsed[issuer][nonce]`).
     * - Requires signer to equal `v.issuer` and hold MINTER_ROLE.
     * - Mints to `v.to` or msg.sender if `v.to==0`.
     *
     * @custom:reverts VoucherExpired if now > validUntil
     * @custom:reverts InvalidSigner  if signer != issuer or lacks MINTER_ROLE
     * @custom:reverts NonceUsed      if voucher nonce already consumed
     */
    function redeemVoucher(MintVoucher calldata v, bytes calldata sig, uint256 rType)
        external nonReentrant whenNotPaused
    {
        if (block.timestamp > v.validUntil) revert VoucherExpired();
        _enforceCap(v.id, v.amount);
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            VOUCHER_TYPEHASH,
            v.id, v.amount,
            keccak256(bytes(v.uri)),
            v.tier, v.expiresAt, v.validUntil,
            v.nonce, v.issuer, v.to
        )));
        address signer = digest.recover(sig);
        if (signer != v.issuer || !hasRole(MINTER_ROLE, signer)) revert InvalidSigner();
        if (_nonceUsed[signer][v.nonce]) revert NonceUsed();
        _nonceUsed[signer][v.nonce] = true;
        _rewardType[v.id] = rType;

        address to = v.to == address(0) ? _msgSender() : v.to;
        _editions[v.id] = EditionInfo({expiresAt: v.expiresAt, tier: v.tier, uri: v.uri});
        _mint(to, v.id, v.amount, "");
        emit MetadataUpdate(v.id);
    }

    /**
     * @notice Read reward type code for id.
     */
    function rewardTypeOf(uint256 id) external view returns (uint256) {
        return _rewardType[id];
    }

    /*──────────────────────── Redemption (burn) ─────────────────────────*/

    /**
    * @notice Burn `amount` of `id` from `from` to redeem rewards.
    * @param from   Token holder (must be caller or approved).
    * @param id     Token id.
    * @param amount Amount to burn (>0).
    *
    * @dev Emits `RewardRedeemed`. Enforces caller authorization via `_requireAuth`.
    *
    * @custom:reverts ZeroAmount if amount == 0
    */
    function redeem(address from, uint256 id, uint256 amount)
        external
        whenNotPaused
    {
        _requireAuth(from);                              // checks msg.sender rights

        if (amount == 0) revert ZeroAmount();
        _burn(from, id, amount);                         // updates cap + hooks
        emit RewardRedeemed(from, id, amount);
    }

    /**
    * @notice Batch version of `redeem`. Length of `ids` and `amounts` must match.
    * @param from     Token holder (must be caller or approved).
    * @param ids      Token ids to burn.
    * @param amounts  Amounts per id (each >0).
    *
    * @custom:reverts LenMismatch if array lengths differ
    * @custom:reverts ZeroAmount  if any amount == 0
    */
    function batchRedeem(
        address from,
        uint256[] calldata ids,
        uint256[] calldata amounts
    ) external whenNotPaused {
        uint256 len = ids.length;
        if (len != amounts.length) revert LenMismatch();
        _requireAuth(from);

        // Validate each pair before burning
        for (uint256 i; i < len; ++i) {
            if (amounts[i] == 0) revert ZeroAmount();
        }

        _burnBatch(from, ids, amounts);                  // OZ helper
        
        for (uint256 i; i < len; ++i) {
            emit RewardRedeemed(from, ids[i], amounts[i]);
        }
    }

    /*──────────────────────── Internal helpers ─────────────────────────*/

    /**
     * @notice Check caller authorization (holder or approved operator).
     * @param from Address to validate against msg.sender.
     * @custom:reverts TransferRoleRequired if neither holder nor approved.
     */
    function _requireAuth(address from) internal view {
        if (from != _msgSender() && !isApprovedForAll(from, _msgSender())) {
            revert TransferRoleRequired();
        }
    }

    /**
     * @notice Per-id URI override (falls back to base URI when empty).
     * @param id Token id.
     * @return string URI string for the token id.
     */
    function uri(uint256 id) public view override returns (string memory) {
        string memory custom = _editions[id].uri;
        return bytes(custom).length > 0 ? custom : super.uri(id);
    }

    /**
     * @notice ERC165 supportsInterface merge.
     */
    function supportsInterface(bytes4 iid)
        public view override(ERC1155Upgradeable, ERC2981Upgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return iid == type(IERC2981).interfaceId
            || super.supportsInterface(iid);
    }

    /**
     * @notice Approve or revoke `operator` using an EIP-712 signature.
     * @param owner     Token owner who signs the approval.
     * @param operator  Operator to set approval for.
     * @param approved  Approval flag.
     * @param deadline  Signature deadline (unix).
     * @param v,r,s     ECDSA signature fields.
     *
     * @dev Nonces are consumed from `_nonces[owner]`. Reverts on expiry or invalid signer.
     *
     * @custom:reverts Expired        if now > deadline
     * @custom:reverts InvalidSigner  if recovered signer != owner
     */
    function permitForAll(
        address owner,
        address operator,
        bool approved,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        if (block.timestamp > deadline) revert Expired();
        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                keccak256("PermitForAll(address owner,address operator,bool approved,uint256 nonce,uint256 deadline)"),
                owner, operator, approved,
                _nonces[owner]++, deadline
            ))
        );
        address signer = ecrecover(digest, v, r, s);
        if (signer != owner) revert InvalidSigner();
        _setApprovalForAll(owner, operator, approved);
    }

    /*──────────────────────── Expiry sweep ─────────────────────────*/

    /**
    * @notice Burn caller’s balances for ids that are past their `expiresAt`.
    * @param ids List of ids to check and burn if expired.
    *
    * @dev Reverts `NoExpired` when none of the provided ids has expired balance.
    */
    function sweepExpired(uint256[] calldata ids) external whenNotPaused {
        uint256 len = ids.length;
        if (len == 0) return;

        // prepare arrays for _burnBatch
        uint256[] memory amounts = new uint256[](len);
        uint256 burnCount;

        for (uint256 i; i < len; ++i) {
            uint256 id = ids[i];
            if (block.timestamp > _editions[id].expiresAt) {
                uint256 bal = balanceOf(_msgSender(), id);
                if (bal != 0) {
                    amounts[i] = bal;
                    burnCount++;
                }
            }
        }

        // no expired balance → nothing to burn
        if (burnCount == 0) revert NoExpired();

        _burnBatch(_msgSender(), ids, amounts); // OZ helper
    }

    /**
    * @notice Admin sweep: burns expired balances of `from` for given ids.
    * @param from Address whose expired balances will be burned.
    * @param ids  List of ids to sweep.
    *
    * @dev Only MINTER_ROLE may call. Reverts `NoExpired` if nothing to burn.
    */
    function sweepExpiredFrom(address from, uint256[] calldata ids)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
    {
        uint256 len = ids.length;
        if (len == 0) return;

        uint256[] memory amounts = new uint256[](len);
        uint256 burnCount;

        for (uint256 i; i < len; ++i) {
            uint256 id = ids[i];
            if (block.timestamp > _editions[id].expiresAt) {
                uint256 bal = balanceOf(from, id);
                if (bal != 0) {
                    amounts[i] = bal;
                    burnCount++;
                }
            }
        }

        if (burnCount == 0) revert NoExpired();
        _burnBatch(from, ids, amounts);
    }

    /*──────────────────────── Whitelist (optional) ─────────────────────*/

    /**
     * @notice Set (or clear) the whitelist registry.
     * @param registry Whitelist contract address (0 to disable checks).
     *
     * @dev Only MINTER_ROLE can call. Checks are enforced in `_enforceWL`.
     */
    function setWhitelist(address registry) external whenNotPaused onlyRole(MINTER_ROLE) {
        whitelist = IWhitelist(registry);
    }

    /**
     * @notice Enforce whitelist checks on non-mint/non-burn transfers when registry is set.
     * @param from Sender (address(0) for mint).
     * @param to   Recipient (address(0) for burn).
     * @custom:reverts TransferRoleRequired if either end is not whitelisted.
     */
    function _enforceWL(address from, address to) internal view {
        if (address(whitelist) == address(0)) return;         // registry not set ⟹ no checks
        if (from == address(0) || to == address(0)) return;   // mint / burn exempt
        if (!whitelist.isWhitelisted(from) || !whitelist.isWhitelisted(to)) revert TransferRoleRequired();
    }

    /*──────────────────────── Core transfer hook & voting ───────────────────*/

    /**
     * @notice Core ERC1155 state change hook (mint/transfer/burn).
     * @param from   Source (address(0) for mint).
     * @param to     Destination (address(0) for burn).
     * @param ids    Token ids array.
     * @param values Corresponding amounts array.
     *
     * @dev
     * - Blocks non-mint/non-burn transfers when `soulbound==true`.
     * - Calls the parent implementation (updates balances & emits events).
     * - Enforces whitelist checks after parent updates.
     * - Updates voting units: `units = tier(id) × amount`, calls `_transferVotingUnits`.
     * - Tracks `_burned` supply for burns.
     *
     * @custom:reverts SoulboundErr if transferring between non-zero addresses while soulbound
     * @custom:reverts TransferRoleRequired if whitelist is set and either end is not allowed
     */
    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) internal virtual override {
        if (from != address(0) && to != address(0)) {
            if (soulbound) revert SoulboundErr();
        }
        // 1) Let OZ mutate balances & emit TransferSingle/TransferBatch
        super._update(from, to, ids, values);
        _enforceWL(from, to);
        
        // 2) Now update Votes: for each id moved, shift (tier × amount)
        for (uint256 i = 0; i < ids.length; ++i) {
            uint8  tier = _editions[ids[i]].tier;
            uint256 amt = values[i];
            uint256 units = uint256(tier) * amt;

            if (to == address(0)) {
                _burned[ids[i]] += values[i];
            }

            if (tier != 0 && amt != 0) {
                if (from != address(0)) _votesBalance[from] -= units;
                if (to   != address(0)) _votesBalance[to]   += units;
                _transferVotingUnits(from, to, units);
            }
        }
    }

    /**
     * @notice VotesUpgradeable hook: read the current voting units for `account`.
     * @param account Address whose voting units are requested.
     * @return uint256 Sum of `tier(id) × balanceOf(account,id)` across all ids (cached).
     */
    function _getVotingUnits(address account)
        internal
        view
        override
        returns (uint256)
    {
        return _votesBalance[account];
    }

    /*──────────────────────── Pausable ───────────────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause() external onlyRole(PAUSER_ROLE){_pause();}

    /**
     * @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
     */
    function unpause() external onlyRole(PAUSER_ROLE){_unpause();}

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /*──────────────────────── Upgrade gate ───────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /*──────────────────────── Storage gap ───────────────────*/
    uint256[44] private __gapPrivilege;
}

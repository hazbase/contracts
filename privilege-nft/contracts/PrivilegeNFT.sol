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

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721VotesUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./extensions/RolesCommon.sol";
import "./extensions/ERC4907Upgradeable.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ───── Whitelist registry (optional) ───── */
interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

/**
 * @title PrivilegeNFT
 *
 * @notice
 * - Purpose: Upgradable ERC-721 membership/privilege NFT with:
 *   * EIP-712 (typed data) + voucher-based **lazy mint**,
 *   * Optional **soulbound** mode (non-transferable between EOAs),
 *   * ERC-2981 **royalty** support,
 *   * ERC-4907 **user** rentals (compatible extension),
 *   * **Voting power** integration (ERC721Votes): each token’s `tier` contributes to holder voting units,
 *   * **Supply cap** locking (collection-wide), **expiry** per token, and **guardian** recovery,
 *   * Optional **whitelist** (KYC) checks on transfers,
 *   * ERC-2771 meta-transactions and **UUPS** upgradeability.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Supply cap: `_enforceCap()` guards mint paths (direct/voucher) respecting `_maxSupply`.
 * - Voucher: nonces are tracked per issuer; signer must hold MINTER_ROLE.
 * - Soulbound: enforced in `_beforeTokenTransfer` for non-mint/burn moves.
 * - Voting units cache: `_cachedVotes` updated in `_update()` and on `setTier()`.
 * - Whitelist: `_enforceWL` requires both ends be whitelisted for transfers (mint/burn exempt).
 * - Upgrade: `_authorizeUpgrade` is gated by ADMIN_ROLE. Meta-tx via ERC-2771 overrides.
 */

contract PrivilegeNFT is
    ERC721URIStorageUpgradeable,
    EIP712Upgradeable,
    ERC4907Upgradeable,
    ERC721VotesUpgradeable,
    ERC2981Upgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable,
    UUPSUpgradeable
{
    using ECDSA for bytes32;

    /*────────────────────────── Errors ─────────────────────────*/
    error NonceAlreadyUsed();
    error InvalidVoucherSigner();
    error VoucherExpired();
    error LenMismatch();
    error SoulboundErr();
    error TransferRoleRequired();
    error SameOwner();
    error NonExistentToken();
    error NotRecipient();
    error InvalidSigner();
    error SignatureExpired();
    error CapZero();
    error AlreadyLocked();
    error CapExceeded();

    /*────────────────────────── Events ─────────────────────────*/
    /// @notice Emitted after a voucher is successfully redeemed.
    event VoucherRedeemed(bytes32 digest, address to, uint8 tier);

    /*────────────────────────── Voucher (EIP-712) ──────────────*/

    /**
     * @notice EIP-712 voucher for lazy minting a single NFT.
     * @param issuer     Address that signs the voucher (must hold MINTER_ROLE).
     * @param to         Intended recipient (address(0) ⇒ msg.sender; else must match caller).
     * @param uri        Token metadata URI.
     * @param expiresAt  Token’s membership expiry (unix seconds).
     * @param tier       Voting tier (weight) for this token.
     * @param validUntil Voucher validity deadline (unix seconds).
     * @param nonce      Unique per-issuer nonce to prevent replay.
     */
    struct MintVoucher {
        address issuer;
        address to;
        string  uri;
        uint64  expiresAt;
        uint8   tier;
        uint64  validUntil;
        uint256 nonce;
    }
    bytes32 private constant VOUCHER_TYPEHASH =
        keccak256("MintVoucher(address issuer,address to,string uri,uint64 expiresAt,uint8 tier,uint64 validUntil,uint256 nonce)");

    /// @dev issuer => (nonce => used?)
    mapping(address => mapping(uint256 => bool)) private _nonceUsed;
    /// @dev per-owner running nonce (optional helper for frontends)
    mapping(address => uint256) private _nonces;

    /// @notice Optional on-chain KYC registry; when set, transfers require both ends whitelisted.
    IWhitelist public whitelist;

    /*────────────────────────── Membership data ───────────────*/

    /**
     * @dev Per-token membership information.
     * - `expiresAt`: token’s expiry timestamp
     * - `tier`:      voting weight contribution for this token
     */
    struct MemberInfo {
        uint64 expiresAt;
        uint8  tier;
    }
    mapping(uint256 => MemberInfo) private _members;   // tokenId → info
    mapping(address => uint256)  private _cachedVotes; // holder → voting units

    /*────────────────────────── Supply cap ────────────────────*/

    /// @dev 0 = unlocked/unlimited; once set, cannot be changed.
    uint256 private _maxSupply;
    /// @dev lifetime minted (includes burned)
    uint256 private _minted;
    /// @dev lifetime burned (for totalSupply computation)
    uint256 private _burned;

    /*────────────────────────── Misc state ────────────────────*/
    uint256 private _nextId;
    bool    public soulbound;

    /*────────────────────────── Contract meta ─────────────────*/
    string private constant CONTRACT_TYPE = "PrivilegeNFT";
    string private constant VERSION       = "1";
    string private _contractURI;

    /**
     * @notice Disable initializers for the implementation (UUPS pattern).
     */
    constructor() { _disableInitializers(); }

    /*────────────────────────── Initializer ───────────────────*/

    /**
     * @notice Initialize the PrivilegeNFT collection.
     * @param name                 ERC-721 name.
     * @param symbol               ERC-721 symbol.
     * @param baseURI              Contract-level URI (returned by `contractURI()`).
     * @param admin                Admin address (granted roles via RolesCommon).
     * @param forwarders           Trusted ERC-2771 forwarders (meta-tx).
     * @param royaltyReceiver      Default royalty receiver (ERC-2981).
     * @param royaltyFeeNumerator  Royalty bps (0..10000).
     *
     * @dev Calls initializers for ERC721, EIP712 (name/version), URIStorage, ERC4907, Votes,
     *      ERC2981, Pausable, ReentrancyGuard, ERC2771, UUPS, and RolesCommon.
     *      Grants MINTER_ROLE to `admin`. Sets `_contractURI` to `baseURI`.
     */
    function initialize(
        string calldata name,
        string calldata symbol,
        string calldata baseURI,
        address   admin,
        address[] calldata forwarders,
        address   royaltyReceiver,
        uint96    royaltyFeeNumerator
    ) external initializer {
        __ERC721_init(name, symbol);
        __EIP712_init(CONTRACT_TYPE, VERSION);
        __ERC721URIStorage_init();
        __ERC4907_init();
        __ERC721Votes_init();
        __ERC2981_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __ERC2771Context_init(forwarders);
        __UUPSUpgradeable_init();
        __RolesCommon_init(admin);

        _setDefaultRoyalty(royaltyReceiver, royaltyFeeNumerator);
        _nextId = 0;
        _contractURI = baseURI;
        _grantRole(MINTER_ROLE, admin);
    }

    /*────────────────────────── Supply-cap logic ──────────────*/

    /**
     * @notice Lock collection-wide maximum supply.
     * @param cap Maximum supply (>0). Cannot be changed once set (one-way lock).
     *
     * @custom:reverts CapZero       if `cap == 0`
     * @custom:reverts AlreadyLocked if `_maxSupply != 0`
     */
    function lockSupply(uint256 cap) external onlyRole(ADMIN_ROLE) {
        if (cap == 0)       revert CapZero();
        if (_maxSupply != 0) revert AlreadyLocked();
        _maxSupply = cap;
    }

    /**
     * @notice Lifetime minted counter (including burned tokens).
     */
    function totalMinted() external view returns (uint256) { return _minted; }

    /**
     * @notice Circulating supply (= minted − burned).
     */
    function totalSupply() public view returns (uint256)   { return _minted - _burned; }

    /**
     * @notice Read collection max supply cap (0 = unlocked/unlimited).
     */
    function maxSupply()  external view returns (uint256)  { return _maxSupply; }

    /**
     * @notice Contract-level metadata URI (base).
     * @return string Base/contract URI.
     */
    function contractURI() public view returns (string memory) {
        return _contractURI;
    }

    /**
     * @notice Internal guard to enforce collection supply cap on mint.
     * @custom:reverts CapExceeded if `_maxSupply != 0` and `_minted + 1 > _maxSupply`
     */
    function _enforceCap() private view {
        if (_maxSupply != 0 && _minted + 1 > _maxSupply) revert CapExceeded();
    }

    /*────────────────────────── Royalty admin ─────────────────*/

    /**
     * @notice Set default royalty.
     * @param receiver Royalty receiver.
     * @param fee      Royalty fee in bps (0..10000).
     *
     * @dev Only ROYALTY_ROLE may call.
     */
    function setDefaultRoyalty(address receiver, uint96 fee) external onlyRole(ROYALTY_ROLE) {
        _setDefaultRoyalty(receiver, fee);
    }

    /**
     * @notice Delete default royalty information.
     * @dev Only ROYALTY_ROLE may call.
     */
    function deleteDefaultRoyalty() external onlyRole(ROYALTY_ROLE) {
        _deleteDefaultRoyalty();
    }

    /*────────────────────────── Direct mint ───────────────────*/

    /**
     * @notice Mint a new token to `to`.
     * @param to   Recipient address.
     * @param uri  Token metadata URI.
     * @param exp  Membership expiry timestamp.
     * @param tier Voting tier (weight) for this token.
     * @return id  Newly minted token id.
     *
     * @dev Only MINTER_ROLE and while not paused. Respects collection cap.
     */
    function safeMint(
        address to,
        string  calldata uri,
        uint64  exp,
        uint8   tier
    ) external whenNotPaused onlyRole(MINTER_ROLE) returns (uint256 id) {
        _enforceCap();
        id = _mintOne(to, uri, exp, tier);
    }

    /*────────────────────────── Voucher (lazy-mint) ───────────*/

    /**
     * @notice Redeem a signed voucher to mint a token.
     * @param v   MintVoucher struct (issuer, to, uri, expiresAt, tier, validUntil, nonce).
     * @param sig ECDSA signature by `v.issuer` over the voucher typed data.
     * @return id Newly minted token id.
     *
     * @dev
     * - Validates voucher expiry (`block.timestamp ≤ validUntil`).
     * - Enforces cap and anti-replay for `(issuer, nonce)`.
     * - Requires signer to equal `v.issuer` and hold MINTER_ROLE.
     * - Resolves recipient: `to = (v.to == 0 ? msg.sender : v.to)`; if `v.to != 0`, caller must be the recipient.
     * - Emits `VoucherRedeemed`.
     *
     * @custom:reverts VoucherExpired       if now > `v.validUntil`
     * @custom:reverts InvalidVoucherSigner if signer != issuer or lacks MINTER_ROLE
     * @custom:reverts NonceAlreadyUsed     if `(issuer, nonce)` has been consumed
     * @custom:reverts NotRecipient         if `v.to != 0` and caller ≠ `v.to`
     */
    function redeemVoucher(
        MintVoucher calldata v,
        bytes          calldata sig
    ) external whenNotPaused nonReentrant returns (uint256 id) {
        if (block.timestamp > v.validUntil) revert VoucherExpired();
        _enforceCap();

        bytes32 digest = _hashTypedDataV4(
            keccak256(abi.encode(
                VOUCHER_TYPEHASH,
                v.issuer,
                v.to,
                keccak256(bytes(v.uri)),
                v.expiresAt,
                v.tier,
                v.validUntil,
                v.nonce
            ))
        );
        address signer = digest.recover(sig);
        if (signer != v.issuer || !hasRole(MINTER_ROLE, signer)) revert InvalidVoucherSigner();
        if (_nonceUsed[signer][v.nonce]) revert NonceAlreadyUsed();
        _nonceUsed[signer][v.nonce] = true;

        address to = v.to == address(0) ? _msgSender() : v.to;
        if (v.to != address(0) && to != _msgSender()) revert NotRecipient();

        id = _mintOne(to, v.uri, v.expiresAt, v.tier);

        emit VoucherRedeemed(digest, v.to, v.tier);
    }

    /*────────────────────────── Internal mint helper ──────────*/

    /**
     * @notice Internal: mint and initialize membership attributes.
     * @param to   Recipient.
     * @param uri  Token URI.
     * @param exp  Expiry timestamp.
     * @param tier Voting tier.
     * @return id  Minted token id.
     *
     * @dev Increments `_nextId` and `_minted`, sets `_members[id]`, mints and sets URI.
     */
    function _mintOne(
        address to,
        string  memory uri,
        uint64  exp,
        uint8   tier
    ) internal returns (uint256 id) {
        id = _nextId;
        unchecked { ++_nextId; }            // monotonic

        _members[id] = MemberInfo({expiresAt: exp, tier: tier});
        _safeMint(to, id);
        _setTokenURI(id, uri);

        unchecked { ++_minted; }            // lifetime counter
        emit MetadataUpdate(id);
    }

    /*────────────────────────── Tier / expiry admin ───────────*/

    /**
     * @notice Update membership expiry for an existing token.
     * @param id     Token id.
     * @param newExp New expiry timestamp.
     *
     * @custom:reverts NonExistentToken if token has not been minted
     */
    function renew(uint256 id, uint64 newExp) external onlyRole(MINTER_ROLE) {
        if (_ownerOf(id) == address(0)) revert NonExistentToken();
        _members[id].expiresAt = newExp;
        emit MetadataUpdate(id);
    }

    /**
     * @notice Update membership tier (voting weight) for an existing token.
     * @param id      Token id.
     * @param newTier New tier value.
     *
     * @dev Adjusts cached votes for the token owner by the delta.
     *
     * @custom:reverts NonExistentToken if token has not been minted
     */
    function setTier(uint256 id, uint8 newTier) external onlyRole(MINTER_ROLE) {
        address owner = _ownerOf(id);
        if (owner == address(0)) revert NonExistentToken();

        uint8 old = _members[id].tier;
        _members[id] = MemberInfo({expiresAt: _members[id].expiresAt, tier: newTier});

        if (newTier > old) _cachedVotes[owner] += (newTier - old);
        else               _cachedVotes[owner] -= (old - newTier);

        emit MetadataUpdate(id);
    }

    /*────────────────────────── Guardian recovery ─────────────*/

    /**
     * @notice Recover a token to `newOwner` (back-office/abuse recovery).
     * @param id        Token id to transfer.
     * @param newOwner  New owner address.
     *
     * @dev Only GUARDIAN_ROLE. Performs an admin transfer (`_transfer`).
     *
     * @custom:reverts NonExistentToken if token does not exist
     * @custom:reverts SameOwner        if `newOwner` is already the owner
     */
    function guardianRecover(uint256 id, address newOwner)
        external
        whenNotPaused
        onlyRole(GUARDIAN_ROLE)
    {
        address cur = ownerOf(id);
        if (cur == address(0)) revert NonExistentToken();
        if (cur == newOwner)   revert SameOwner();
        _transfer(cur, newOwner, id);
    }

    /*────────────────────────── Whitelist (optional) ──────────*/

    /**
     * @notice Set or clear the whitelist registry.
     * @param registry Whitelist contract address (0 to disable checks).
     *
     * @dev Only MINTER_ROLE. Checks are enforced in `_beforeTokenTransfer`.
     */
    function setWhitelist(address registry) external whenNotPaused onlyRole(MINTER_ROLE) {
        whitelist = IWhitelist(registry);
    }

    /**
     * @notice Enforce whitelist checks on non-mint/non-burn transfers when registry is set.
     * @param from Sender (address(0) for mint).
     * @param to   Recipient (address(0) for burn).
     *
     * @custom:reverts TransferRoleRequired if either party is not whitelisted
     */
    function _enforceWL(address from, address to) internal view {
        if (address(whitelist) == address(0)) return;         // registry not set ⟹ no checks
        if (from == address(0) || to == address(0)) return;   // mint / burn exempt
        require(whitelist.isWhitelisted(from), "SENDER_NOT_WHITELISTED");
        require(whitelist.isWhitelisted(to),   "RECIP_NOT_WHITELISTED");
    }

    /*────────────────────────── Transfer hooks ─────────────────*/

    /**
     * @notice Pre-transfer hook.
     * @param from Current owner (address(0) for mint).
     * @param to   New owner (address(0) for burn).
     * @param id   Token id.
     *
     * @dev Enforces whitelist and soulbound rules; reverts if paused.
     *
     * @custom:reverts SoulboundErr         if moving between non-zero addresses and `soulbound` is true
     * @custom:reverts TransferRoleRequired if whitelist registry is set and either party is not whitelisted
     */
    function _beforeTokenTransfer(address from, address to, uint256 id)
        internal
        override(ERC4907Upgradeable)
        whenNotPaused
    {
        _enforceWL(from, to);
        if (from != address(0) && to != address(0)) {
            if (soulbound) revert SoulboundErr();
        }
        super._beforeTokenTransfer(from, to, id);
    }

    /*────────────────────────── ERC-721Votes plumbing ─────────*/

    /**
     * @notice Voting units for an account (ERC721Votes hook).
     * @param account Address to query.
     * @return uint256 Cached voting units for `account`.
     */
    function _getVotingUnits(address account)
        internal
        view
        override(ERC721VotesUpgradeable)
        returns (uint256)
    { return _cachedVotes[account]; }

    /**
     * @notice Core token state update (transfer/mint/burn) with vote cache adjustments.
     * @param to      New owner (or address(0) for burn).
     * @param tokenId Token id being moved.
     * @param auth    Authorization context (from OZ).
     * @return address Previous owner address.
     *
     * @dev Updates `_cachedVotes` for `from`/`to` by the token’s `tier`, then delegates to parents.
     */
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable, ERC721VotesUpgradeable)
        returns (address)
    {
        address from = _ownerOf(tokenId);
        if (from != address(0)) _beforeTokenTransfer(from, to, tokenId);

        uint256 weight = _members[tokenId].tier;
        if (from != address(0)) _cachedVotes[from] -= weight;
        if (to   != address(0)) _cachedVotes[to]   += weight;

        return super._update(to, tokenId, auth);
    }

    /**
     * @notice Burn token id and clear membership; updates burn counter.
     * @param id Token id to burn.
     */
    function _burn(uint256 id)
        internal
        override(ERC721Upgradeable)
    {
        super._burn(id);
        delete _members[id];
        unchecked { ++_burned; }
    }

    /*────────────────────────── EIP-712 permitForAll ─────────*/

    /**
     * @notice Approve `operator` to manage all of `owner`’s tokens via EIP-712 signature.
     * @param owner     Token owner (signer).
     * @param operator  Operator to approve/revoke.
     * @param approved  Approval flag.
     * @param deadline  Signature expiry (unix seconds).
     * @param v,r,s     ECDSA signature fields.
     *
     * @dev Consumes `_nonces[owner]`. Reverts on expiration or invalid signer.
     *
     * @custom:reverts SignatureExpired if now > `deadline`
     * @custom:reverts InvalidSigner     if recovered signer != `owner`
     */
    function permitForAll(
        address owner,
        address operator,
        bool    approved,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        if (block.timestamp > deadline) revert SignatureExpired();

        bytes32 digest = _hashTypedDataV4(keccak256(
            abi.encode(
                keccak256("PermitForAll(address owner,address operator,bool approved,uint256 nonce,uint256 deadline)"),
                owner, operator, approved, _nonces[owner]++, deadline
            )
        ));
        if (digest.recover(v, r, s) != owner) revert InvalidSigner();

        _setApprovalForAll(owner, operator, approved);
    }

    /*────────────────────────── Introspection / misc ─────────*/

    /**
     * @notice ERC165 supportsInterface merge.
     */
    function supportsInterface(bytes4 iid)
        public
        view
        override(ERC721Upgradeable, ERC2981Upgradeable, ERC4907Upgradeable, ERC721URIStorageUpgradeable, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return
            iid == type(IERC2981).interfaceId   ||
            iid == type(VotesUpgradeable).interfaceId ||
            iid == type(IERC4907Upgradeable).interfaceId ||
            iid == type(IERC4906).interfaceId  ||
            super.supportsInterface(iid);
    }

    /**
     * @notice tokenURI passthrough to URIStorage.
     */
    function tokenURI(uint256 tokenId) public view virtual override(ERC721Upgradeable,ERC721URIStorageUpgradeable) returns (string memory) {
        return super.tokenURI(tokenId);
    }

    /**
     * @notice Voting hook plumbing (OZ internal).
     */
    function _increaseBalance(address account, uint128 amount) internal virtual override(ERC721Upgradeable,ERC721VotesUpgradeable) {
        super._increaseBalance(account, amount);
    }

    /*────────────────────────── Pause / Unpause ──────────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause(); }

    /**
     * @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
     */
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // meta-tx ---------------------------------------------------------------

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /*────────────────────────── Upgrade gate ─────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /*────────────────────────── Storage gap ──────────────────*/
    uint256[40] private __gapPrivilege;
}

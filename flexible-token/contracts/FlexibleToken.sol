// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.22;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//   https://hazbase.com

import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20VotesUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

/**
 *  @title FlexibleToken
 *
 *  @notice
 *  - Purpose: Single ERC20Votes-based token that can be configured at deploy-time to act as:
 *      * GovernanceToken-like  : transferable, optionally capped supply, typical 18 decimals
 *      * SupporterToken-like   : soul-bound (non-transferable), uncapped or capped, e.g., 0 decimals
 *  - Configuration knobs:
 *      * `cap` (0 = unlimited), `decimals` (uint8), and `transferable` (false ⇒ soul-bound)
 *      * Optional whitelist registry enforcing sender/recipient checks on transfers/mints/burns
 *  - Features:
 *      * EIP-712 voucher-based mint (`redeemVoucher`) signed by an address holding MINTER_ROLE
 *      * ERC20Votes snapshotting of voting power (compatible with OZ Governor)
 *      * Pausable, UUPS upgradeable, ERC-2771 meta-transactions, Roles-based access control
 *
 *  @dev SECURITY / AUDIT NOTES
 *  - Cap enforcement: All mints (including voucher redemption) check `cap` if non-zero.
 *  - Soul-bound mode: When `transferable == false`, non-mint/non-burn transfers revert.
 *  - Whitelist: If set, both `from` and `to` must be whitelisted for token movements (mint/burn exempt).
 *  - Voucher replay: Digest is tracked in `redeemed` mapping. Signer must hold MINTER_ROLE and equal `v.issuer`.
 *  - Upgradeability: `_authorizeUpgrade` is gated by ADMIN_ROLE; storage gap reserved.
 *  - Meta-tx: ERC-2771-enabled `_msgSender/_msgData`.
 */
 
contract FlexibleToken is
    Initializable,
    ERC20Upgradeable,
    ERC20VotesUpgradeable,
    PausableUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    ReentrancyGuardUpgradeable,
    RolesCommonUpgradeable
{
    using ECDSA for bytes32;

    /*────────────────────── Events ─────────────────────────────*/

    /// @notice Emitted when cap is changed by admin.
    event CapChanged(uint256 oldCap, uint256 newCap);
    /// @notice Emitted when the whitelist registry is configured (or replaced).
    event WhitelistConfigured(address indexed whitelist);
    /// @notice Emitted on successful voucher redemption.
    event VoucherRedeemed(bytes32 digest, address to, uint256 amount);

    /*──────────────────────── Config ───────────────────────────*/

    /// @notice If false, the token behaves as soul-bound (non-transferable).
    bool    public transferable;          // false = soul-bound token
    /// @dev Max total supply; 0 means unlimited.
    uint256 private _cap;                // 0 = unlimited
    /// @dev ERC-20 decimals reported by `decimals()`.
    uint8   private _decimals;           // e.g. 18 for GT, 0 for ST

    /// @notice Optional whitelist registry (may be unset = address(0)).
    IWhitelist public whitelist;

    /**
     * @dev EIP-712 voucher struct for off-chain authorized mints.
     * - `issuer` must sign and must hold MINTER_ROLE at redemption time.
     * - `to==address(0)` means recipient is `_msgSender()`.
     * - `validUntil` is a unix timestamp; redemption must happen before or at it.
     * - `nonce` is included in the digest; replay is prevented by `redeemed[digest]`.
     */
    struct MintVoucher {
        address issuer;
        address to;        // 0x0 ⇒ _msgSender()
        uint256 amount;
        uint64  validUntil;
        uint256 nonce;
    }

    /// @dev Permit-like EIP-712 typehash for MintVoucher.
    bytes32 private constant _MINT_VOUCHER_TYPEHASH =
        keccak256("MintVoucher(address issuer,address to,uint256 amount,uint64 validUntil,uint256 nonce)");

    /// @notice EIP-712 digest replay protection.
    mapping(bytes32 => bool) public redeemed;

    /*──────────────────── Constructor ─────────────────────────*/

    /**
     * @notice Disable initializers for the logic contract (UUPS pattern).
     */
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() { _disableInitializers(); }

    /*──────────────────── Initializer ─────────────────────────*/

    /**
     * @notice Initialize the token (proxy).
     * @param name_          Token name.
     * @param symbol_        Token symbol.
     * @param treasury       Receiver of the initial supply & MINTER_ROLE.
     * @param initialSupply  Amount minted to treasury.
     * @param cap_           Total supply cap (0 ⇒ unlimited).
     * @param decimals_      ERC-20 decimals (e.g., 18 or 0).
     * @param transferable_  true = transferable; false = soul-bound.
     * @param admin          DEFAULT_ADMIN_ROLE & UPGRADER_ROLE holder (timelock recommended).
     * @param forwarders     ERC-2771 trusted forwarders.
     *
     * @dev
     * - Sets roles (ADMIN, MINTER to `admin` & `treasury`).
     * - Mints `initialSupply` to `treasury` (cap-checked).
     * - Initializes ERC20Votes and Pausable, UUPS, ReentrancyGuard, ERC2771, and RolesCommon.
     *
     * @custom:reverts treasury zero if treasury == address(0)
     * @custom:reverts admin zero    if admin == address(0)
     * @custom:reverts cap too low   if cap_ > 0 and cap_ < initialSupply
     * @custom:reverts invalid decimals if decimals_ > 18
     */
    function initialize(
        string memory  name_,
        string memory  symbol_,
        address        treasury,
        uint256        initialSupply,
        uint256        cap_,
        uint8          decimals_,
        bool           transferable_,
        address        admin,
        address[] calldata forwarders
    ) external initializer {
        require(treasury != address(0), "treasury zero");
        require(admin    != address(0), "admin zero");
        if (cap_ > 0) require(cap_ >= initialSupply, "cap too low");
        require(decimals_ <= 18, "invalid decimals");

        __ERC20_init(name_, symbol_);
        __ERC20Votes_init();
        __AccessControl_init();
        __Pausable_init();
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        _cap         = cap_;
        _decimals    = decimals_;
        transferable = transferable_;

        _grantRole(MINTER_ROLE, admin);
        _grantRole(MINTER_ROLE, treasury);
        if (initialSupply > 0) _mint(treasury, initialSupply);
    }

    /*──────────────────── Overrides ───────────────────────────*/

    /**
     * @notice Report ERC-20 decimals.
     * @return uint8 The configured decimals value.
     */
    function decimals() public view override returns (uint8) { return _decimals; }

    /*──────────────────── Mint / Burn ─────────────────────────*/

    /**
     * @notice Mint tokens to `to` (MINTER_ROLE).
     * @param to     Recipient address.
     * @param amount Amount to mint.
     *
     * @dev Checks cap if non-zero. Pausable-protected.
     * @custom:reverts cap exceeded if totalSupply() + amount > cap
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        if (_cap > 0) require(totalSupply() + amount <= _cap, "cap exceeded");
        _mint(to, amount);
    }

    /**
     * @notice Batch mint to multiple recipients (MINTER_ROLE).
     * @param to       Recipients array.
     * @param amounts  Amounts array (same length as `to`).
     *
     * @dev Sums total to pre-check cap (if non-zero). Pausable-protected.
     * @custom:reverts len mismatch if `to.length != amounts.length`
     * @custom:reverts overflow     if intermediate sum overflows
     * @custom:reverts cap exceeded if cap would be exceeded by batch
     */
    function batchMint(address[] calldata to, uint256[] calldata amounts)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
    {
        require(to.length == amounts.length, "len mismatch");

        if (_cap > 0) {
            uint256 total;
            for (uint256 i; i < amounts.length; ++i) {
                total += amounts[i];
                require(total >= amounts[i], "overflow");
            }
            require(totalSupply() + total <= _cap, "cap exceeded");
        }

        for (uint256 i; i < to.length; ++i) {
            _mint(to[i], amounts[i]);
        }
    }

    /**
     * @notice Burn tokens from `from` (MINTER_ROLE).
     * @param from    Address to burn from.
     * @param amount  Amount to burn.
     *
     * @dev Pausable-protected. No cap update needed (cap is max totalSupply).
     */
    function burn(address from, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        _burn(from, amount);
    }

    /**
     * @notice Batch burn from multiple addresses (MINTER_ROLE).
     * @param from     Holder addresses.
     * @param amounts  Amounts to burn per holder.
     *
     * @dev Pausable-protected.
     * @custom:reverts len mismatch if `from.length != amounts.length`
     */
    function batchBurn(address[] calldata from, uint256[] calldata amounts)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
    {
        require(from.length == amounts.length, "len mismatch");
        for (uint256 i; i < from.length; ++i) _burn(from[i], amounts[i]);
    }

    /*── Voucher (optional airdrop) ───────────────────────────*/

    /**
     * @notice Redeem a signed mint voucher (EIP-712) and mint to `v.to` or caller.
     * @param v    MintVoucher struct (issuer, to, amount, validUntil, nonce).
     * @param sig  ECDSA signature by `v.issuer` over the EIP-712 typed data.
     * @return uint256 The amount minted.
     *
     * @dev
     * - Rejects expired vouchers and replays (`redeemed[digest]`).
     * - Signer must hold MINTER_ROLE and equal `v.issuer`.
     * - Respects cap if non-zero.
     * - Emits `VoucherRedeemed`.
     *
     * @custom:reverts voucher expired if `block.timestamp > v.validUntil`
     * @custom:reverts cap exceeded    if mint would exceed cap
     * @custom:reverts voucher used    on replay
     * @custom:reverts bad signer      if recovered signer lacks MINTER_ROLE
     * @custom:reverts issuer mismatch if signer != v.issuer
     */
    function redeemVoucher(MintVoucher calldata v, bytes calldata sig)
        external nonReentrant whenNotPaused returns (uint256)
    {
        require(block.timestamp <= v.validUntil, "voucher expired");
        if (_cap > 0) require(_cap - totalSupply() >= v.amount, "cap exceeded");

        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            _MINT_VOUCHER_TYPEHASH,
            v.issuer,
            v.to,
            v.amount,
            v.validUntil,
            v.nonce
        )));
        require(!redeemed[digest], "voucher used");
        address signer = digest.recover(sig);
        require(hasRole(MINTER_ROLE, signer), "bad signer");
        require(signer == v.issuer, "issuer mismatch");

        redeemed[digest] = true;
        address recipient = v.to == address(0) ? _msgSender() : v.to;
        _mint(recipient, v.amount);
        emit VoucherRedeemed(digest, recipient, v.amount);
        return v.amount;
    }

    /*────────────────── Cap Management ───────────────────────*/

    /**
     * @notice Update cap; 0 means unlimited.
     * @param newCap New cap value.
     *
     * @dev Only ADMIN_ROLE. Must be >= current totalSupply if non-zero.
     *      Emits `CapChanged(oldCap, newCap)`.
     * @custom:reverts invalid cap if newCap != 0 && newCap < totalSupply()
     */
    function setCap(uint256 newCap) external onlyRole(ADMIN_ROLE) {
        require(newCap == 0 || newCap >= totalSupply(), "invalid cap");
        emit CapChanged(_cap, newCap);
        _cap = newCap;
    }

    /**
     * @notice Read current cap (0 means unlimited).
     * @return uint256 Cap value.
     */
    function cap() external view returns (uint256) { return _cap; }

    /*────────────────── Whitelist (optional) ────────────────*/

    /**
     * @notice Set or replace the whitelist registry.
     * @param registry Whitelist contract address (or zero to disable checks).
     *
     * @dev Only GUARDIAN_ROLE. Emits `WhitelistConfigured`.
     */
    function setWhitelist(address registry) external onlyRole(GUARDIAN_ROLE) {
        whitelist = IWhitelist(registry);
        emit WhitelistConfigured(registry);
    }

    /**
     * @notice Enforce whitelist on non-mint/burn transfers if registry is set.
     * @param from Sender address.
     * @param to   Recipient address.
     *
     * @dev Mint/burn (involving address(0)) are exempt.
     * @custom:reverts SENDER_NOT_WL / RECIP_NOT_WL if registry denies either party.
     */
    function _enforceWL(address from, address to) internal view {
        if (address(whitelist) == address(0)) return;
        if (from == address(0) || to == address(0)) return;
        require(whitelist.isWhitelisted(from), "SENDER_NOT_WL");
        require(whitelist.isWhitelisted(to),   "RECIP_NOT_WL");
    }

    /*─────────────── Internal Overrides ─────────────────────*/

    /**
     * @notice Core ERC20/Votes balance update hook with pause, soul-bound, and whitelist enforcement.
     * @param from    Sender (address(0) for mint).
     * @param to      Recipient (address(0) for burn).
     * @param amount  Transfer amount.
     *
     * @dev When `transferable == false`, only mint or burn are allowed; user-to-user transfers revert.
     *      Pausable is enforced via modifier, then whitelist checked, then super._update.
     */
    function _update(address from, address to, uint256 amount)
        internal override(ERC20Upgradeable, ERC20VotesUpgradeable) whenNotPaused
    {
        _enforceWL(from, to);
        if (!transferable && from != address(0) && to != address(0)) {
            revert("Soulbound: transfer disabled");
        }
        super._update(from, to, amount);
    }

    /*──────────────── Pause Control ─────────────────────────*/

    /**
     * @notice Pause state-changing entrypoints (PAUSER_ROLE).
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause(); }

    /**
     * @notice Unpause state-changing entrypoints (PAUSER_ROLE).
     */
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    /*───────────────── Meta-tx overrides ───────────────────*/

    /**
     * @dev ERC-2771 meta-tx sender override.
     */
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /**
     * @dev ERC-2771 meta-tx data override.
     */
    function _msgData()   internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /*──────────────── Storage Gap ───────────────────────────*/

    /**
     * @dev Reserved storage to allow future variable additions while preserving layout.
     */
    uint256[43] private __gap;
}

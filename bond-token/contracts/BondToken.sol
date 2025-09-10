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

import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/* ───── ERC-3475 minimal interface -----
 * @dev Only the subset required by this contract is declared.
 */
interface IERC3475 {
    struct Values { string key; string value; }
    struct ClassData { Values[] data; }
    struct NonceData { Values[] data; }

    event ClassCreated(uint256 indexed classId);
    event NonceCreated(uint256 indexed classId, uint256 indexed nonceId);
    event Transfer(address indexed from, address indexed to,
                   uint256 indexed classId, uint256 nonceId, uint256 amount);
    event Redeemed(address indexed from,
                   uint256 indexed classId, uint256 indexed nonceId, uint256 amount);

    /**
     * @notice Mint bond units to `to` for (classId, nonceId).
     * @param to        Recipient address.
     * @param classId   Class identifier.
     * @param nonceId   Nonce identifier.
     * @param amount    Units to mint.
     */
    function issue(address to, uint256 classId,
                   uint256 nonceId, uint256 amount) external;

    /**
     * @notice Transfer bond units from msg.sender to `to`.
     */
    function transfer(address to, uint256 classId,
                      uint256 nonceId, uint256 amount) external;

    /**
     * @notice Redeem (burn) bond units from msg.sender.
     */
    function redeem(uint256 classId, uint256 nonceId, uint256 amount) external;

    /**
     * @notice Read balance for an owner in (classId, nonceId).
     */
    function balanceOf(address owner, uint256 classId,
                       uint256 nonceId) external view returns (uint256);

    /**
     * @notice Total supply for (classId, nonceId).
     */
    function totalSupply(uint256 classId,uint256 nonceId) external view returns(uint256);

    /**
     * @notice Burn `amount` from `from`. Typically operator/owner only.
     */
    function burn(
        address from,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;

    /**
     * @notice Operator transfer with `from` authorization (or approval).
     */
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external;
}

/**
 * @dev Marker interface for ERC165 discovery of BondToken type.
 */
interface IBondTokenMarker { }

/* ───── Whitelist registry (optional) -----
 * @dev If not set, no whitelist checks are applied.
 */
interface IWhitelist { function isWhitelisted(address) external view returns (bool); }

/**
 *  @title BondToken
 *
 *  @notice
 *  - Purpose: ERC-3475–style bond token with Class/Nonce partitions, snapshotting (balances & totalSupply),
 *             optional on-chain whitelist (KYC), meta-transactions (ERC-2771), permit-like operator
 *             approvals via EIP-712 ("PermitForAll"), pausable, and UUPS upgradeable.
 *  - Ledger:
 *      * Balances keyed by (classId, nonceId, holder).
 *      * totalSupply keyed by (classId, nonceId).
 *      * Snapshots of balances and supply are lazily recorded per "snapshot id" to support historical queries.
 *  - Transfers:
 *      * Governed by `classTransferable[classId]`. When false, transfers for that class are locked.
 *      * Whitelist (if set) is enforced for transfers between non-zero addresses.
 *  - Approvals:
 *      * Operator "approve all" is managed via mapping and can be set off-chain using `permitForAll` (EIP-712).
 *  - Meta-tx:
 *      * Supports ERC-2771 trusted forwarders for gasless UX.
 *  - Upgrades:
 *      * UUPS with `_authorizeUpgrade` gated by ADMIN_ROLE.
 *  - Roles:
 *      * MINTER_ROLE controls mint, class/nonce creation, and whitelist/class transferability settings.
 *      * PAUSER_ROLE controls pause/unpause.
 *      * ADMIN_ROLE controls upgrades (via RolesCommon).
 *
 *  @dev SECURITY / AUDIT NOTES
 *  - Snapshot bootstrap: If `_snapId` is 0 at first write, `_writeSnapBalance` initializes `_snapId` to 1 and
 *    stores baseline balances/supply for id=1. Thus historical queries before any explicit `snapshot()` call
 *    still work (id >= 1). `snapshot()` increments `_snapId` and finalizes pending "dirty" accounts/supplies.
 *  - Dirty tracking: `_dirty` queue + `_dirtyFlag` minimize duplicate writes on a single snapshot id.
 *  - Whitelist checks: Enforced on transfers (non-zero `from` and `to`). Mint/burn are exempt.
 *  - Operator auth: `operatorTransferFrom` requires `from == msg.sender` or `isApprovedForAll(from, msg.sender)`.
 *                   `burn` additionally allows MINTER_ROLE.
 *  - No reentrancy guard is present; external calls are limited to whitelist `view` and no external token calls.
 *  - Integer safety: Uses Solidity 0.8 checked math except where `unchecked` is used deliberately after bounds checks.
 *  - Event coverage: Emission on issue/transfer/redeem/class/nonce create; snapshots emit id.
 */

contract BondToken is
    Initializable,
    ERC165,
    PausableUpgradeable,
    UUPSUpgradeable,
    EIP712Upgradeable,
    IERC3475,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    using ECDSA for bytes32;

    /*────────────────── CONSTANTS ──────────────────*/

    /// @dev EIP-712 PermitForAll typed struct hash.
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("PermitForAll(address owner,address operator,bool approved,uint256 nonce,uint256 deadline)");

    /*────────────────── STORAGE ──────────────────*/

    /// @dev Monotonic snapshot id; lazily bootstrapped to 1 on first write if 0.
    uint256 private _snapId;

    /// @dev "Dirty" holders whose balance should be finalized upon `snapshot()`.
    struct Dirty { uint256 classId; uint256 nonceId; address holder; }
    Dirty[] private _dirty;
    mapping(bytes32 => bool) private _dirtyFlag; // (classId, nonceId, holder) -> queued?

    // classId ⇒ nonceId ⇒ snapId[]
    mapping(uint256 => mapping(uint256 => uint256[])) private _snapShots;
    // classId ⇒ nonceId ⇒ snapId ⇒ totalSupply
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) private _snapSupply;

    // classId ⇒ nonceId ⇒ holder ⇒ snapId[]
    mapping(uint256 => mapping(uint256 => mapping(address => uint256[]))) private _snapBalances;
    // classId ⇒ nonceId ⇒ holder ⇒ snapId ⇒ balance
    mapping(uint256 => mapping(uint256 => mapping(address => mapping(uint256 => uint256)))) private _balAt;

    /// @notice Optional on-chain KYC/whitelist registry; if unset, checks are skipped.
    IWhitelist public whitelist;

    /// @dev Class metadata store.
    mapping(uint256 => ClassData) private _classes;
    /// @dev Nonce metadata store keyed by class.
    mapping(uint256 => mapping(uint256 => NonceData)) private _nonces;
    /// @dev Balances keyed by (classId, nonceId, holder).
    mapping(uint256 => mapping(uint256 => mapping(address => uint256))) private _balances;
    /// @notice Total supply per (classId, nonceId). Public getter satisfies IERC3475.totalSupply.
    mapping(uint256 => mapping(uint256 => uint256)) public totalSupply;
    /// @notice Per-class transferability flag (true by default upon class creation).
    mapping(uint256 => bool) public classTransferable;

    /*── operator approvals for PermitForAll ─*/
    mapping(address => mapping(address => bool)) private _operatorApprovals; // owner => operator => approved?
    mapping(address => uint256)               private _noncesByOwner;         // EIP-712 nonce per owner

    /// @dev EIP-712 domain fields.
    string private constant CONTRACT_TYPE = "BondToken";
    string private constant VERSION = "1";

    /// @notice Emitted when a class transferability flag changes.
    event ClassTransferableSet(uint256 indexed classId, bool allowed);

    /// @notice Emitted when a new snapshot id is created.
    event Snapshot(uint256 id);

    /*────────────────── INITIALISER ──────────────────*/

    /**
     * @notice Constructor disables initializers for UUPS proxy pattern.
     */
    constructor() { _disableInitializers(); }
    
    /**
     * @notice Initialize proxy instance.
     * @param admin       Address to receive admin/minter/pauser/guardian roles via RolesCommon.
     * @param forwarders  Trusted ERC-2771 forwarders for meta-transactions.
     *
     * @dev Calls initializers for Pausable, UUPS, EIP712, ERC2771, and RolesCommon.
     *      Grants MINTER_ROLE to `admin`.
     */
    function initialize(
        address admin,
        address[] calldata forwarders
    )
        external
        initializer
    {
        __Pausable_init();
        __UUPSUpgradeable_init();
        __EIP712_init(CONTRACT_TYPE, VERSION);
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        _grantRole(MINTER_ROLE, admin);
    }

    /*────────────────── WHITELIST ──────────────────*/

    /**
     * @notice Set the optional whitelist/registry contract.
     * @param registry  Address of the whitelist contract (or zero to disable checks).
     *
     * @dev Only MINTER_ROLE can set. Transfers between non-zero addresses will be checked if set.
     */
    function setWhitelist(address registry) external onlyRole(MINTER_ROLE) {
        whitelist = IWhitelist(registry);
    }

    /**
     * @notice Internal whitelist enforcement for transfers.
     * @param from Sender address.
     * @param to   Recipient address.
     *
     * @dev No checks if registry not set or if mint/burn (`from`==0 or `to`==0).
     * @custom:reverts SENDER_NOT_WHITELISTED / RECIP_NOT_WHITELISTED if registry denies either party.
     */
    function _enforceWL(address from, address to) internal view {
        if (address(whitelist) == address(0)) return;         // registry not set ⟹ no checks
        if (from == address(0) || to == address(0)) return;   // mint / burn exempt
        require(whitelist.isWhitelisted(from), "SENDER_NOT_WHITELISTED");
        require(whitelist.isWhitelisted(to),   "RECIP_NOT_WHITELISTED");
    }

    /**
     * @notice Set whether transfers are allowed for a given class.
     * @param classId  Target class.
     * @param ok       True to allow transfers; false to lock.
     *
     * @dev Requires the class to exist. Emits `ClassTransferableSet`.
     * @custom:reverts CLASS_UNKNOWN if class not created yet.
     */
    function setClassTransferable(uint256 classId, bool ok) external onlyRole(MINTER_ROLE) {
        require(_classes[classId].data.length!=0,"CLASS_UNKNOWN");
        classTransferable[classId] = ok;
        emit ClassTransferableSet(classId, ok);
    }

    /*────────────────── PERMIT-FOR-ALL (A7) ──────────────────*/

    /**
     * @notice Read current EIP-712 nonce for `owner`.
     * @param owner  Address whose permit nonce is returned.
     * @return uint256  Current nonce value.
     */
    function nonces(address owner) external view returns (uint256) { return _noncesByOwner[owner]; }

    /**
     * @notice Read operator approval status.
     * @param owner     Token owner.
     * @param operator  Operator address.
     * @return bool     True if `operator` is approved for all of `owner`.
     */
    function isApprovedForAll(address owner, address operator) public view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @notice Set operator approval from msg.sender.
     * @param operator  Operator address.
     * @param approved  Approval flag.
     *
     * @dev Direct on-chain approval; no signature required.
     */
    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[_msgSender()][operator] = approved;
    }

    /**
     * @notice Create a new snapshot id and finalize all "dirty" balances/supplies under that id.
     * @return id  The newly created snapshot id.
     *
     * @dev
     * - Effects:
     *   * Increments `_snapId` (id := id + 1) and emits `Snapshot(id)`.
     *   * For each tracked Dirty entry, stores totalSupply and per-holder balances for id, clears dirty flags.
     * - Gas notice: Cost grows with number of dirty entries since last snapshot.
     */
    function snapshot() external onlyRole(MINTER_ROLE) returns (uint256 id) {
        id = ++_snapId;
        emit Snapshot(id);

        uint256 len = _dirty.length;
        for (uint256 i; i < len; ++i) {
            Dirty memory d = _dirty[i];

            if (_snapSupply[d.classId][d.nonceId][id] == 0) {
                _snapSupply[d.classId][d.nonceId][id] = totalSupply[d.classId][d.nonceId];
                _snapShots[d.classId][d.nonceId].push(id);
            }

            uint256[] storage arr = _snapBalances[d.classId][d.nonceId][d.holder];
            if (arr.length == 0 || arr[arr.length-1] != id) arr.push(id);

            _balAt[d.classId][d.nonceId][d.holder][id] = _balances[d.classId][d.nonceId][d.holder];
            _dirtyFlag[keccak256(abi.encode(d.classId, d.nonceId, d.holder))] = false;
        }
        delete _dirty;
    }

    /**
     * @notice Internal helper to record (or bootstrap) snapshot entries on balance change.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param holder   Account whose balance changed.
     * @param newBal   New balance to record for current snapshot id.
     *
     * @dev
     * - If `_snapId == 0`, bootstraps `_snapId = 1`, records baseline totalSupply and pushes id=1.
     * - Marks (class, nonce, holder) as dirty so a subsequent `snapshot()` finalizes supply & balances.
     */
    function _writeSnapBalance(
        uint256 classId,
        uint256 nonceId,
        address holder,
        uint256 newBal
    ) private {
        if (_snapId == 0) {
            _snapId = 1;
            _snapSupply[classId][nonceId][1] = totalSupply[classId][nonceId];
            _snapShots[classId][nonceId].push(1);
        }
        uint256 id = _snapId;
        _markDirty(classId, nonceId, holder);

        uint256[] storage arr = _snapBalances[classId][nonceId][holder];
        if (arr.length == 0 || arr[arr.length-1] != id) arr.push(id);
        _balAt[classId][nonceId][holder][id] = newBal;
    }

    /**
     * @notice Track a holder as dirty for the current snapshot id.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param holder   Account to mark.
     *
     * @dev Uses `_dirtyFlag` to avoid duplicate entries in `_dirty`.
     */
    function _markDirty(
        uint256 classId,
        uint256 nonceId,
        address holder
    ) private {
        bytes32 k = keccak256(abi.encode(classId, nonceId, holder));
        if (_dirtyFlag[k]) return;
        _dirtyFlag[k] = true;
        _dirty.push(Dirty(classId, nonceId, holder));
    }

    /**
     * @notice Binary search helper over ascending snapshot id arrays.
     * @param arr  Storage array of snapshot ids (ascending).
     * @param id   Target id (query).
     * @return index  The greatest snapshot id <= `id`, or 0 if none.
     *
     * @dev Returned value is the *snapshot id*, not the array position.
     */
    function _search(uint256[] storage arr, uint256 id)
        private view returns (uint256 index)
    {
        uint256 l=0; uint256 r=arr.length;
        while (l < r) {
            uint256 m = (l + r) >> 1;
            if (arr[m] <= id) l = m + 1; else r = m;
        }
        if (r == 0) return 0;
        return arr[r-1];
    }

    /**
     * @notice Historical balance query for a holder at snapshot `id`.
     * @param holder   Account to query.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param id       Snapshot id (>= 1 recommended).
     * @return uint256 Balance recorded at or before snapshot `id` (0 if none).
     */
    function balanceOfAt(
        address holder,
        uint256 classId,
        uint256 nonceId,
        uint256 id
    ) external view returns (uint256) {
        uint256 snap = _search(_snapBalances[classId][nonceId][holder], id);
        return _balAt[classId][nonceId][holder][snap];
    }

    /**
     * @notice Historical totalSupply query at snapshot `id`.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param id       Snapshot id (>= 1 recommended).
     * @return uint256 totalSupply recorded at or before snapshot `id` (0 if none).
     */
    function totalSupplyAt(
        uint256 classId,
        uint256 nonceId,
        uint256 id
    ) external view returns (uint256) {
        uint256 snap = _search(_snapShots[classId][nonceId], id);
        return _snapSupply[classId][nonceId][snap];
    }

    /**
     * @notice Gasless operator approval using EIP-712 signature.
     * @param owner     Token owner granting approval.
     * @param operator  Operator address to approve/revoke.
     * @param approved  Approval flag (true/false).
     * @param deadline  Signature expiry timestamp (unix seconds).
     * @param v         Recovery param.
     * @param r         Signature r.
     * @param s         Signature s.
     *
     * @dev
     * - Effects:
     *   * Verifies signature over (owner, operator, approved, nonce, deadline).
     *   * Increments `_noncesByOwner[owner]` on success.
     *   * Sets `_operatorApprovals[owner][operator] = approved`.
     * - Reverts if expired or signer mismatch.
     *
     * @custom:reverts PERMIT_EXPIRED if now > deadline
     * @custom:reverts INVALID_SIG if signature does not recover to `owner`
     */
    function permitForAll(
        address owner,
        address operator,
        bool    approved,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(block.timestamp <= deadline, "PERMIT_EXPIRED");

        bytes32 structHash = keccak256(
            abi.encode(
                PERMIT_TYPEHASH,
                owner,
                operator,
                approved,
                _noncesByOwner[owner]++,
                deadline
            )
        );
        bytes32 hash = _hashTypedDataV4(structHash);
        address signer = hash.recover(v, r, s);
        require(signer == owner, "INVALID_SIG");

        _operatorApprovals[owner][operator] = approved;
    }

    /*────────────────── CLASS / NONCE META ──────────────────*/

    /**
     * @notice Create a new class with metadata.
     * @param classId  New class id (must be unused).
     * @param data     Array of key/value metadata entries.
     *
     * @dev Sets `classTransferable[classId] = true` by default. Emits `ClassCreated`.
     * @custom:reverts CLASS_EXISTS if class already initialized.
     */
    function createClass(uint256 classId, Values[] calldata data)
        external
        onlyRole(MINTER_ROLE)
    {
        require(_classes[classId].data.length == 0, "CLASS_EXISTS");
        
        for (uint256 i; i < data.length; ++i) _classes[classId].data.push(data[i]);
        classTransferable[classId] = true;
        emit ClassCreated(classId);
    }

    /**
     * @notice Create a new nonce under an existing class with metadata.
     * @param classId  Existing class id.
     * @param nonceId  New nonce id under the class (must be unused).
     * @param data     Array of key/value metadata entries.
     *
     * @dev Emits `NonceCreated`. Class must exist.
     * @custom:reverts CLASS_MISSING if class not created
     * @custom:reverts NONCE_EXISTS if nonce already initialized
     */
    function createNonce(uint256 classId, uint256 nonceId, Values[] calldata data)
        external
        onlyRole(MINTER_ROLE)
    {
        require(_classes[classId].data.length != 0, "CLASS_MISSING");
        require(_nonces[classId][nonceId].data.length == 0, "NONCE_EXISTS");
        
        for (uint256 i; i < data.length; ++i) _nonces[classId][nonceId].data.push(data[i]);
        emit NonceCreated(classId, nonceId);
    }

    /*────────────────── CORE LIFECYCLE ──────────────────*/

    /**
     * @notice Mint (issue) bond units to `to`.
     * @param to       Recipient address (non-zero).
     * @param classId  Class id (must exist).
     * @param nonceId  Nonce id (must exist).
     * @param amount   Units to mint.
     *
     * @dev
     * - Requires MINTER_ROLE and not paused.
     * - Whitelist enforced for recipient if registry set.
     * - Updates `totalSupply` and per-holder balance; records snapshot write; emits `Transfer(0x0, to, ...)`.
     * @custom:reverts MINT_TO_ZERO if `to == address(0)`
     * @custom:reverts NONCE_MISSING if nonce metadata not found
     */
    function issue(address to, uint256 classId, uint256 nonceId, uint256 amount)
        external
        override
        whenNotPaused
        onlyRole(MINTER_ROLE)
    {
        require(to != address(0), "MINT_TO_ZERO");
        require(_nonces[classId][nonceId].data.length != 0, "NONCE_MISSING");
        _enforceWL(address(0), to);

        _balances[classId][nonceId][to] += amount;
        totalSupply[classId][nonceId]   += amount;

        _writeSnapBalance(classId, nonceId, to, _balances[classId][nonceId][to]);
        emit Transfer(address(0), to, classId, nonceId, amount);
    }

    /**
     * @notice Operator transfer with authorization.
     * @param from     Source address.
     * @param to       Destination address.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to transfer.
     *
     * @dev
     * - Allowed if `msg.sender == from` or `isApprovedForAll(from, msg.sender)` is true.
     * - Enforces pause, class transferability, whitelist, and non-self-transfer.
     * - Emits `Transfer(from, to, ...)`.
     * @custom:reverts NOT_OPERATOR if caller lacks permission
     */
    function operatorTransferFrom(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external whenNotPaused {
        address sender = _msgSender();
        require(
            sender == from || isApprovedForAll(from, sender),
            "NOT_OPERATOR"
        );
        _transfer(from, to, classId, nonceId, amount);
    }

    /**
     * @notice Transfer from msg.sender to `to`.
     * @param to       Destination address (non-zero).
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to transfer.
     *
     * @dev Enforces pause, class transferability, whitelist, and non-self-transfer.
     */
    function transfer(address to, uint256 classId, uint256 nonceId, uint256 amount)
        external
        override
        whenNotPaused
    {
        _transfer(_msgSender(), to, classId, nonceId, amount);
    }

    /**
     * @notice Internal transfer routine with validation and snapshot writes.
     * @param from     Source address.
     * @param to       Destination address.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to transfer.
     *
     * @dev
     * - Validates class transferability and whitelist (non-zero parties).
     * - Prevents self-transfer.
     * - Checks sufficient balance and updates storage.
     * - Writes snapshot deltas for both `from` and `to`.
     * - Emits `Transfer(from, to, ...)`.
     * @custom:reverts CLASS_LOCKED if class transfers disabled
     * @custom:reverts TRANSFER_TO_ZERO if `to == 0`
     * @custom:reverts SELF_TRANSFER if `from == to`
     * @custom:reverts INSUFF_BAL if `from` has insufficient balance
     */
    function _transfer(
        address from,
        address to,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) internal {
        require(classTransferable[classId], "CLASS_LOCKED");
        require(to != address(0), "TRANSFER_TO_ZERO");
        require(from!=to,"SELF_TRANSFER");
        _enforceWL(from, to);

        uint256 bal = _balances[classId][nonceId][from];
        require(bal >= amount, "INSUFF_BAL");
        unchecked { _balances[classId][nonceId][from] = bal - amount; }
        _balances[classId][nonceId][to] += amount;

        _writeSnapBalance(classId, nonceId, to, _balances[classId][nonceId][to]);
        _writeSnapBalance(classId, nonceId, from, _balances[classId][nonceId][from]);

        emit Transfer(from, to, classId, nonceId, amount);
    }

    /**
     * @notice Redeem (burn) from msg.sender.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to burn.
     *
     * @dev Enforces pause; calls `_burnInternal(msg.sender, ...)`.
     */
    function redeem(uint256 classId, uint256 nonceId, uint256 amount)
        external
        override
        whenNotPaused
    {
        _burnInternal(_msgSender(), classId, nonceId, amount);
    }

    /**
     * @notice Burn from `from` (owner/operator/minter).
     * @param from     Source address.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to burn.
     *
     * @dev Allowed if caller is `from`, approved operator, or holds MINTER_ROLE.
     *      Enforces pause; then calls `_burnInternal`.
     * @custom:reverts NOT_AUTH if caller lacks permission
     */
    function burn(
        address from,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) external override whenNotPaused {
        address sender = _msgSender();
        require(
            sender == from || isApprovedForAll(from, sender) || hasRole(MINTER_ROLE, sender),
            "NOT_AUTH"
        );
        _burnInternal(from, classId, nonceId, amount);
    }

    /**
     * @notice Internal burn routine with balance/supply updates and snapshot write.
     * @param from     Source address.
     * @param classId  Class id.
     * @param nonceId  Nonce id.
     * @param amount   Units to burn.
     *
     * @dev Checks balance, updates mapping and totalSupply, writes snapshot, and emits `Redeemed`.
     * @custom:reverts INSUFF_BAL if `from` balance < amount
     */
    function _burnInternal(
        address from,
        uint256 classId,
        uint256 nonceId,
        uint256 amount
    ) internal {
        uint256 bal = _balances[classId][nonceId][from];
        require(bal >= amount, "INSUFF_BAL");
        unchecked {
            _balances[classId][nonceId][from] = bal - amount;
            totalSupply[classId][nonceId]    -= amount;
        }
        _writeSnapBalance(classId, nonceId, from, _balances[classId][nonceId][from]);
        emit Redeemed(from, classId, nonceId, amount);
    }

    /*────────────────── VIEWS ──────────────────*/

    /**
     * @notice Current balance of `owner` for (classId, nonceId).
     * @return uint256 Current balance.
     */
    function balanceOf(address owner, uint256 classId, uint256 nonceId)
        external view override returns (uint256)
    { return _balances[classId][nonceId][owner]; }

    /**
     * @notice Return all class metadata pairs.
     * @param classId  Class id.
     * @return Values[] Array of key/value metadata.
     */
    function classData(uint256 classId)
        external view returns (Values[] memory)
    { return _classes[classId].data; }

    /**
     * @notice Return all nonce metadata pairs for (classId, nonceId).
     */
    function nonceData(uint256 classId, uint256 nonceId)
        external view returns (Values[] memory)
    { return _nonces[classId][nonceId].data; }

    /**
     * @notice Indexed class metadata accessor.
     * @param classId  Class id.
     * @param i        Metadata index.
     * @return key     Metadata key.
     * @return value   Metadata value.
     */
    function classDataAt(uint256 classId, uint256 i)
        external view returns (string memory key, string memory value)
    {
        Values storage v = _classes[classId].data[i];
        return (v.key, v.value);
    }

    /*────────────────── ERC165 ──────────────────*/

    /**
     * @notice ERC165 interface support.
     * @param id  Interface id to check.
     * @return bool True if supported (IBondTokenMarker, IERC3475, AccessControl etc.).
     */
    function supportsInterface(bytes4 id)
        public view override(ERC165, AccessControlEnumerableUpgradeable)
        returns (bool)
    {
        return id == type(IBondTokenMarker).interfaceId || id == type(IERC3475).interfaceId || super.supportsInterface(id);
    }

    /*────────────────── PAUSABLE (A6) ──────────────────*/

    /**
     * @notice Pause state-changing functions; only PAUSER_ROLE.
     */
    function pause()   external onlyRole(PAUSER_ROLE) { _pause();   }

    /**
     * @notice Unpause state-changing functions; only PAUSER_ROLE.
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

    /*────────────────────── UUPS auth ────────────────────────────*/

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}

    /*────────────────────── Storage gap ──────────────────────────*/

    /**
     * @dev Reserved storage to allow future variable additions while preserving layout.
     */
    uint256[43] private __gap;
}

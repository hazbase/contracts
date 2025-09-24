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

import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";

/*────────────────────────── External verifier interface ─────────────────────────*/
/**
 * @title IVerifier
 * @notice Minimal zk-SNARK verifier interface (e.g., Groth16). Concrete circuit semantics
 *         are external; this contract only checks public signals alignment prior to call.
 */
interface IVerifier {
    /**
     * @notice Verify a proof for the provided public inputs (circuit-specific).
     * @param a,b,c        Proof elements
     * @param publicSignals Public inputs; expected indexing is circuit dependent
     * @return bool        True if proof is valid
     */
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata publicSignals
    ) external view returns (bool);
}

/*────────────────────────── Operator mask helpers ─────────────────────────*/
/**
 * @dev Bit mask for allowed comparison operators in zk checks.
 * GT=1, LT=2, EQ=4 .. combinations allowed (e.g., 1|4).
 */
library CompareMask {
    uint8 internal constant NONE = 0; // KYC only
    uint8 internal constant GT   = 1;
    uint8 internal constant LT   = 2;
    uint8 internal constant NEQ  = 3; // GT | LT
    uint8 internal constant EQ   = 4;
    uint8 internal constant GTE  = 5; // GT | EQ
    uint8 internal constant LTE  = 6; // LT | EQ
    uint8 internal constant ALL  = 7; // GT | LT | EQ
}

/**  @title MultiTrustCredential
//
//   @notice
//   - Purpose: Non-transferable credential NFT (tokenId = owner address) that stores
//     typed “metrics” per holder (e.g., reputation scores, KYC flags, commitment hashes),
//     supports role-gated mint/update, optional ZK proof verification against stored
//     commitments, and punitive slashing.
//   - Design highlights:
//       * ERC721URIStorageUpgradeable: each credential has a metadata URI.
//       * tokenId = uint256(uint160(owner)): one token per address; minted lazily on first write.
//       * Metric registry: admin defines metric ids, UI labels, role required, and compare mask.
//       * Updates: writers with the required role can mint/update metrics (single/batch).
//       * ZK verify: external `IVerifier` is used to verify a Groth16-style proof against
//         on-chain commitment (`leafFull`) and holder address. Comparison operator permissions
//         are enforced via `compareMask`.
//       * Slashing: `SLASHER_ROLE` can reduce numeric metric values.
//   - Security / Audit notes:
//       * Metrics are keyed by (tokenId, metricId); writers must hold `metricRole[metricId]`.
//       * `proveMetric` checks both holder binding and commitment equality before verifier call.
//       * Mask semantics: bits 0..2 correspond to GTE/LTE/EQ operators (see CompareMask).
//       * UUPS upgrade gated by ADMIN_ROLE. ERC-2771 meta-tx supported.
*/

contract MultiTrustCredential is
    ERC721URIStorageUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    /*────────────────── Roles ──────────────────*/

    /// @notice Role authorized to slash metric values.
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    /*────────────────── Data ───────────────────*/

    /**
     * @dev Stored metric (per tokenId, metricId).
     * - `value`     : current numeric value (or placeholder if commitment-only)
     * - `leafFull`  : commitment/hash (circuit-dependent)
     * - `timestamp` : last update time (seconds)
     */
    struct Metric { uint32 value; uint256 leafFull; uint32 timestamp; }

    /**
     * @dev Input for single mint.
     * - `uri` is set as tokenURI on first mint for the address.
     */
    struct MetricInput  { bytes32 metricId; uint32 value; uint256 leafFull; string uri; }

    /**
     * @dev Input for an update; `deadline` kept for future EIP-712 support (not enforced here).
     */
    struct MetricUpdate { bytes32 metricId; uint32 newValue; uint256 leafFull; uint256 deadline; }

    /**
     * @dev Batch mint item; creates token if absent and sets tokenURI on first write.
     */
    struct MintItem { address to; bytes32 metricId; uint32 value; uint256 leafFull; string uri; }

    /**
     * @dev Batch update item for an existing token.
     */
    struct UpdateItem { uint256 tokenId; bytes32 metricId; uint32 newValue; uint256 leafFull; }

    /// @dev tokenId => (metricId => Metric)
    mapping(uint256 => mapping(bytes32 => Metric)) private _metrics;

    /**
     * @notice Per-metric freeze flag for compare-mask updates.
     * @dev When true, writers cannot change the compare operator mask via `setCompareMask`.
     *      This is useful to stabilize policy during critical windows (e.g., governance voting).
     *      Controlled by ADMIN_ROLE through `setMaskFrozen`.
     */
    mapping(bytes32 => bool) public maskFrozen;

    // Dynamic registry (admin-managed)
    /// @notice Metric id ⇒ role required to write this metric (writer role).
    mapping(bytes32 => bytes32) public metricRole;
    /// @notice Metric id ⇒ human-readable label (UI hint).
    mapping(bytes32 => string)  public metricLabel;
    /// @notice Metric id ⇒ if true, treat as commitment-only (store hash, value may be placeholder).
    mapping(bytes32 => bool)    public isCommitmentMetric;
    /// @notice Metric id ⇒ allowed comparison operators bitmask (see CompareMask).
    mapping(bytes32 => uint8)   public compareMask;

    /*────────────────── ZK ─────────────────────*/

    /// @notice External verifier contract for zk proof checks.
    IVerifier public verifier;

    /*────────────────── Events ─────────────────*/
    event MetricRegistered(bytes32 indexed id, string label, bytes32 role, uint8 mask);
    event MetricUpdated(uint256 indexed tokenId, bytes32 indexed metricId, uint32 newValue, uint256 leafFull);
    event MetricRevoked(uint256 indexed tokenId, bytes32 indexed metricId, uint32 prevValue, uint256 prevLeaf);
    event Slash(uint256 indexed tokenId, bytes32 indexed metricId, uint32 penalty);
    event CompareMaskChanged(bytes32 indexed id, uint8 oldMask, uint8 newMask, address indexed editor);
    event VerifierSet(address verifier);
    event MaskFrozenSet(bytes32 id, bool frozen);

    /*────────────────── Init ───────────────────*/

    /**
     * @notice Disable initializers for the implementation (UUPS pattern).
     */
    constructor() { _disableInitializers(); }

    /**
     * @notice Initialize the credential system.
     * @param admin       Admin address for RolesCommon (granted admin/pauser/… as configured there).
     * @param _verifier   ZK verifier contract address.
     * @param forwarders  Trusted ERC-2771 forwarders for meta-transactions.
     *
     * @dev
     * - Sets token name/symbol: "MultiTrust Credential" / "MTC".
     * - Emits `VerifierSet`.
     */
    function initialize(address admin, address _verifier, address[] calldata forwarders) external initializer {
        __ERC721_init("MultiTrust Credential", "MTC");
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        verifier = IVerifier(_verifier);
        emit VerifierSet(_verifier);
    }

    /*────────────────── Registry ───────────────*/

    /**
     * @notice Register a new metric type.
     * @param id         Unique metric id (bytes32).
     * @param label      UI label (non-empty).
     * @param roleName   Writer role required to mint/update this metric.
     * @param commitment If true, treat as commitment metric (hash-only semantics).
     * @param mask       Allowed comparison ops bitmask (0..7; GTE=1, LTE=2, EQ=4).
     *
     * @dev Fails if the metric id already exists. Emits `MetricRegistered`.
     *
     * @custom:reverts MTC: metric exists if the id was already registered
     * @custom:reverts bad mask           if mask > 7
     * @custom:reverts MTC: empty label   if label has zero length
     * @custom:reverts empty writer role  if roleName == 0x0
     */
    function registerMetric(
        bytes32 id,
        string  calldata label,
        bytes32 roleName,
        bool    commitment,
        uint8   mask
    ) external onlyRole(ADMIN_ROLE) {
        require(
            metricRole[id] == bytes32(0) &&
            bytes(metricLabel[id]).length == 0,
            "MTC: metric exists"
        );
        require(roleName != bytes32(0), "empty writer role");
        require(mask <= 7, "bad mask");
        require(bytes(label).length > 0, "MTC: empty label");

        metricRole[id]         = roleName;
        metricLabel[id]        = label;
        isCommitmentMetric[id] = commitment;
        compareMask[id]        = mask;
        emit MetricRegistered(id, label, roleName, mask);
    }

    /**
    * @notice Freeze or unfreeze compare-mask updates for a metric.
    * @param id     Metric id to toggle the freeze flag for.
    * @param frozen If true, blocks `setCompareMask` for this metric; if false, allows updates again.
    *
    * @dev ADMIN-only control to prevent policy drift during sensitive periods (e.g., active proposals).
    *      Emits `MaskFrozenSet`.
    */
    function setMaskFrozen(bytes32 id, bool frozen) external onlyRole(ADMIN_ROLE) {
        _assertRegistered(id);
        maskFrozen[id] = frozen;
        emit MaskFrozenSet(id, frozen);
    }

    /**
     * @notice Update the allowed comparison mask for a metric.
     * @param id   Metric id.
     * @param mask New mask (0..7; bitwise OR of CompareMask flags).
     *
     * @dev Caller must hold the metric’s writer role; contract must not be paused.
     *      Respects `maskFrozen`: when frozen, updates are blocked.
     *
     * @custom:reverts metric unregistered if id not registered
     * @custom:reverts role              if caller lacks metric writer role
     * @custom:reverts bad mask          if mask > 7
     * @custom:reverts mask frozen       if admin has frozen updates for this metric
     */
    function setCompareMask(bytes32 id, uint8 mask) external whenNotPaused {
        _assertRegistered(id);
        require(!maskFrozen[id], "mask frozen");
        require(hasRole(metricRole[id], _msgSender()), "role");
        require(mask <= 7, "bad mask");

        uint8 old = compareMask[id];
        if (old == mask) return;

        compareMask[id] = mask;
        emit CompareMaskChanged(id, old, mask, _msgSender());
    }

    /**
     * @notice Internal: ensure metric id is registered.
     * @param id Metric id.
     * @custom:reverts metric unregistered if not registered
     */
    function _assertRegistered(bytes32 id) internal view {
        require(metricRole[id] != bytes32(0), "metric unregistered");
    }

    /*──────────────── Mint ─────────────────────*/

    /**
     * @notice Mint a credential token for `to` (if absent) and set a metric.
     * @param to    Recipient address. tokenId is derived as `uint256(uint160(to))`.
     * @param data  MetricInput: {metricId, value, leafFull, uri}.
     *
     * @dev
     * - Requires writer role for `data.metricId`.
     * - If token not yet minted for `to`, mints and sets tokenURI to `data.uri`.
     * - Stores metric and emits `MetricUpdated`.
     *
     * @custom:reverts metric unregistered if metric id not registered
     * @custom:reverts role              if caller lacks writer role
     * @custom:reverts already minted    if token already exists for `to`
     */
    function mint(address to, MetricInput calldata data)
        external whenNotPaused nonReentrant
    {
        _assertRegistered(data.metricId);
        require(hasRole(metricRole[data.metricId], _msgSender()), "role");
        if (isCommitmentMetric[data.metricId]) {
            require(data.value == 0, "value not allowed for commitment metric");
        }

        uint256 tokenId = uint256(uint160(to));
        require(_ownerOf(tokenId) == address(0), "already minted");

        _safeMint(to, tokenId);
        _setTokenURI(tokenId, data.uri);
        _metrics[tokenId][data.metricId] = Metric({ value: data.value, leafFull: data.leafFull, timestamp: uint32(block.timestamp) });
        emit MetricUpdated(tokenId, data.metricId, data.value, data.leafFull);
    }

    /**
     * @notice Batch mint and/or write metrics.
     * @param arr Array of MintItem {to, metricId, value, leafFull, uri}.
     *
     * @dev
     * - Length is limited to 200 per call for gas safety.
     * - For each item: ensure registration & role, mint if absent (set URI), then write metric.
     * - Emits `MetricUpdated` per write.
     *
     * @custom:reverts too many if `arr.length > 200`
     */
    function mintBatch(MintItem[] calldata arr)
        external whenNotPaused nonReentrant
    {
        require(arr.length <= 200, "too many");
        for (uint256 i; i < arr.length; ++i) {
            MintItem calldata it = arr[i];
            _assertRegistered(it.metricId);
            require(hasRole(metricRole[it.metricId], _msgSender()), "role");
            if (isCommitmentMetric[it.metricId]) {
                require(it.value == 0, "value not allowed for commitment metric");
            }

            uint256 tokenId = uint256(uint160(it.to));
            if (_ownerOf(tokenId) == address(0)) {
                _safeMint(it.to, tokenId);
                _setTokenURI(tokenId, it.uri);
            }
            _metrics[tokenId][it.metricId] = Metric({
                value: it.value,
                leafFull: it.leafFull,
                timestamp: uint32(block.timestamp)
            });
            emit MetricUpdated(tokenId, it.metricId, it.value, it.leafFull);
        }
    }

    /*──────────────── Update ───────────────────*/

    /**
     * @notice Update a metric for an existing token.
     * @param tokenId Credential token id (derived from owner address).
     * @param upd     MetricUpdate {metricId, newValue, leafFull, deadline}.
     *
     * @dev Requires writer role and existing token. Emits `MetricUpdated`.
     *
     * @custom:reverts metric unregistered if id not registered
     * @custom:reverts role              if caller lacks writer role
     * @custom:reverts token absent      if token does not exist
     */
    function updateMetric(uint256 tokenId, MetricUpdate calldata upd)
        external whenNotPaused nonReentrant
    {
        _assertRegistered(upd.metricId);
        require(hasRole(metricRole[upd.metricId], _msgSender()), "role");
        require(_ownerOf(tokenId) != address(0), "token absent");
        if (isCommitmentMetric[upd.metricId]) {
            require(upd.newValue == 0, "value not allowed for commitment metric");
        }

        _metrics[tokenId][upd.metricId] = Metric({
            value: upd.newValue,
            leafFull: upd.leafFull,
            timestamp: uint32(block.timestamp)
        });
        emit MetricUpdated(tokenId, upd.metricId, upd.newValue, upd.leafFull);
    }

    /**
     * @notice Batch update metrics.
     * @param arr Array of UpdateItem {tokenId, metricId, newValue, leafFull}.
     *
     * @dev Length limited to 200 per call. Emits `MetricUpdated` per item.
     *
     * @custom:reverts too many     if `arr.length > 200`
     * @custom:reverts metric unregistered / role / token absent — per item checks
     */
    function updateMetricBatch(UpdateItem[] calldata arr)
        external whenNotPaused nonReentrant
    {
        require(arr.length <= 200, "too many");
        for (uint256 i; i < arr.length; ++i) {
            UpdateItem calldata it = arr[i];
            _assertRegistered(it.metricId);
            require(hasRole(metricRole[it.metricId], _msgSender()), "role");
            require(_ownerOf(it.tokenId) != address(0), "token absent");
            if (isCommitmentMetric[it.metricId]) {
                require(it.newValue == 0, "value not allowed for commitment metric");
            }

            _metrics[it.tokenId][it.metricId] = Metric({
                value: it.newValue,
                leafFull: it.leafFull,
                timestamp: uint32(block.timestamp)
            });
            emit MetricUpdated(it.tokenId, it.metricId, it.newValue, it.leafFull);
        }
    }

    /**
     * @notice Revoke a metric by zeroing both its `value` and `leafFull` commitment.
     * @param tokenId  Credential token id (derived from holder address).
     * @param metricId Metric id to revoke.
     *
     * @dev Requires the metric’s writer role. Emits `MetricRevoked` with pre-revocation values.
     *
     * @custom:reverts metric unregistered if the metric id has not been registered
     * @custom:reverts role              if caller lacks the metric writer role
     * @custom:reverts token absent      if the holder token does not exist
     * @custom:reverts not issued        if neither value nor commitment had been set
     */
    function revokeMetric(uint256 tokenId, bytes32 metricId) external whenNotPaused {
        _assertRegistered(metricId);
        require(hasRole(metricRole[metricId], _msgSender()), "role");
        require(_ownerOf(tokenId) != address(0), "token absent");

        Metric storage m = _metrics[tokenId][metricId];
        // Optional: ensure it had some issuance
        require(m.value != 0 || m.leafFull != 0, "not issued");

        uint32 prevValue = m.value;
        uint256 prevLeaf = m.leafFull;

        m.value = 0;
        m.leafFull = 0;
        m.timestamp = uint32(block.timestamp);

        emit MetricRevoked(tokenId, metricId, prevValue, prevLeaf);
    }

    /*──────────────── ZK Verification ──────────*/

    /**
     * @notice Verify a zk proof for a given metric of a token.
     * @param tokenId     Credential token id (derived from holder address).
     * @param metricId    Metric type id.
     * @param a,b,c       zk proof elements (Groth16-style).
     * @param pubSignals  Public inputs expected by the circuit. This method expects:
     *                      - pubSignals[0] = op (0 = EQ-only/KYC flag, 1=GTE, 2=LTE, 3=EQ)
     *                      - pubSignals[3] = holder address (uint160) for binding
     *                      - pubSignals[5] = commitment (`leafFull`) to match on-chain
     * @return ok         True if verifier accepts the proof.
     *
     * @dev
     * - Enforces address binding and commitment equality with stored metric.
     * - Enforces that the chosen operator `op` is allowed by `compareMask[metricId]`.
     * - Calls external verifier; reverts if verifier returns false.
     *
     * @custom:reverts addr mism   if pubSignals[3] != ownerOf(tokenId)
     * @custom:reverts commit mism if pubSignals[5] != stored commitment
     * @custom:reverts not KYC metric if op==0 but mask != 0 (reserved semantics)
     * @custom:reverts op not allowed if op bit is not set in `compareMask`
     * @custom:reverts proof fail  if verifier returns false
     */
    function proveMetric(
        uint256 tokenId,
        bytes32 metricId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata pubSignals
    ) external view whenNotPaused returns (bool ok) {
        require(pubSignals[3] == uint256(uint160(ownerOf(tokenId))), "addr mism");
        require(pubSignals[5] == _metrics[tokenId][metricId].leafFull, "commit mism");

        uint8 op = uint8(pubSignals[0]);
        uint8 mask = compareMask[metricId];

        if (op == 0) {
            require(mask == 0, "not KYC metric");
        } else {
            require((mask & op) == op, "op not allowed");
        }

        ok = verifier.verifyProof(a, b, c, pubSignals);
        require(ok, "proof fail");
    }

    /**
     * @notice Reduce (slash) a metric’s numeric value for an offender.
     * @param offender Address whose token is targeted (tokenId = uint160(offender)).
     * @param metricId Metric type to slash.
     * @param penalty  Amount to subtract from current value (must be > 0).
     *
     * @dev Caller must hold SLASHER_ROLE. Updates timestamp and emits `Slash`.
     *
     * @custom:reverts 0            if penalty == 0
     * @custom:reverts underflow    if current value < penalty
     */
    function slash(address offender, bytes32 metricId, uint32 penalty) external onlyRole(SLASHER_ROLE) {
        _assertRegistered(metricId);
        require(penalty > 0, '0');
        uint256 tokenId = uint256(uint160(offender));
        Metric storage m = _metrics[tokenId][metricId];
        require(m.value >= penalty, "underflow");
        m.value -= penalty;
        m.timestamp = uint32(block.timestamp);
        emit Slash(tokenId, metricId, penalty);
    }

    /// @notice Read a metric for (tokenId, metricId)
    function getMetric(uint256 tokenId, bytes32 metricId)
        external
        view
        returns (uint32 value, uint256 leafFull, uint32 timestamp)
    {
        Metric storage m = _metrics[tokenId][metricId];
        return (m.value, m.leafFull, m.timestamp);
    }

    /// @notice Helper to compute tokenId from subject address
    function tokenIdOf(address subject) external pure returns (uint256) {
        return uint256(uint160(subject));
    }

    /// @dev Block transfers to enforce soulbound semantics
    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721Upgradeable)
        returns (address)
    {
        address from = _ownerOf(tokenId);
        // allow mint (from == address(0)) and burn (to == address(0)) if you need
        require(from == address(0) || to == address(0), "SBT: non-transferable");
        return super._update(to, tokenId, auth);
    }

    /**
     * @notice ERC165 interface support (merge of parents).
     * @param id Interface id.
     * @return bool Whether supported.
     */
    function supportsInterface(bytes4 id)
        public view override(AccessControlEnumerableUpgradeable, ERC721URIStorageUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(id);
    }

    /*──────────────── Pause / Upgrade ─────────*/

    /**
     * @notice Pause state-changing entrypoints; only PAUSER_ROLE.
     */
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }

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

    /**
     * @notice Authorize UUPS upgrade; only ADMIN_ROLE.
     */
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}
}

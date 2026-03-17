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

// External verifier interfaces
// Minimal zk-SNARK verifier interface, for example a Groth16 verifier.
interface IVerifier {
    /// @notice Verify a proof for the provided public inputs (circuit-specific).
    /// @param a Proof element a.
    /// @param b Proof element b.
    /// @param c Proof element c.
    /// @param publicSignals Public inputs; expected indexing is circuit dependent.
    /// @return True if proof is valid.
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata publicSignals
    ) external view returns (bool);
}

// Fixed-length verifier variants for ZKEx predicates.
interface IVerifier8 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata publicSignals
    ) external view returns (bool);
}

interface IVerifier9 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[9] calldata publicSignals
    ) external view returns (bool);
}

interface IVerifier10 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[10] calldata publicSignals
    ) external view returns (bool);
}

// NOTE: Interfaces are declared for ERC-165 interfaceId computation.
interface IMultiTrustCredentialCore {
    function registerMetric(bytes32,string calldata,bytes32,bool,uint8) external;
    function setCompareMask(bytes32,uint8) external;
    function setMaskFrozen(bytes32,bool) external;
    function mint(address, MultiTrustCredential.MetricInput calldata) external;
    function mintBatch(MultiTrustCredential.MintItem[] calldata) external;
    function updateMetric(uint256, MultiTrustCredential.MetricUpdate calldata) external;
    function updateMetricBatch(MultiTrustCredential.UpdateItem[] calldata) external;
    function revokeMetric(uint256, bytes32) external;
    function slash(address, bytes32, uint32) external;
    function getMetric(uint256, bytes32) external view returns (uint32,uint256,uint32);
    function tokenIdOf(address) external view returns (uint256);
}

interface IMultiTrustCredentialZK {
    function proveMetric(uint256,bytes32,uint256[2] calldata,uint256[2][2] calldata,uint256[2] calldata,uint256[6] calldata) external view returns (bool);
}

interface IMultiTrustCredentialZKEx {
    function provePredicate(uint256,bytes32,bytes32,bytes calldata,uint256[] calldata) external view returns (bool);
}

// Operator mask helpers
/// @dev Bit mask for allowed comparison operators in zk checks.
/// GT=1, LT=2, EQ=4; combinations such as 1|4 are allowed.
library CompareMask {
    // Bit flags (base)
    uint16 internal constant GT  = 1 << 0; // 0b0001
    uint16 internal constant LT  = 1 << 1; // 0b0010
    uint16 internal constant EQ  = 1 << 2; // 0b0100
    //uint16 internal constant IN  = 1 << 3; // 0b1000 (allowlist membership)
    // Aliases / composites
    uint16 internal constant NONE = 0;           // KYC-only (no compare)
    uint16 internal constant NE   = GT | LT;     // not equal
    uint16 internal constant GTE  = GT | EQ;
    uint16 internal constant LTE  = LT | EQ;
    uint16 internal constant ALL  = GT | LT | EQ;
}

/**
 * @title MultiTrustCredential
 *
 * @notice
 * - Purpose: Non-transferable credential NFT, where `tokenId = owner address`, storing
 *   typed metrics per holder such as reputation scores, KYC flags, or commitment hashes.
 * - Supports role-gated mint and update flows, optional ZK proof verification against stored
 *   commitments, and punitive slashing for numeric metrics.
 * - Design highlights:
 *     * ERC721URIStorageUpgradeable: each credential has a metadata URI.
 *     * `tokenId = uint256(uint160(owner))`: one token per address, minted lazily on first write.
 *     * Metric registry: admin defines metric ids, UI labels, role required, and compare mask.
 *     * Updates: writers with the required role can mint or update metrics, singly or in batch.
 *     * ZK verify: external `IVerifier` verifies a proof against the stored commitment (`leafFull`)
 *       and holder address, while `compareMask` constrains which comparisons are allowed.
 *     * Slashing: `SLASHER_ROLE` can reduce numeric metric values.
 *
 * @dev SECURITY / AUDIT NOTES
 * - Metrics are keyed by `(tokenId, metricId)`, and writers must hold `metricRole[metricId]`.
 * - `proveMetric` checks both holder binding and commitment equality before invoking the verifier.
 * - Mask semantics: bits 0..2 correspond to GT, LT, and EQ operators in `CompareMask`.
 * - UUPS upgradeability is gated by ADMIN_ROLE and ERC-2771 meta-transactions are supported.
 */

contract MultiTrustCredential is
    ERC721URIStorageUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    UUPSUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    // Interfaces

    bytes4 private constant _IID_MTC_CORE =
        IMultiTrustCredentialCore.registerMetric.selector ^
        IMultiTrustCredentialCore.setCompareMask.selector ^
        IMultiTrustCredentialCore.setMaskFrozen.selector ^
        IMultiTrustCredentialCore.mint.selector ^
        IMultiTrustCredentialCore.mintBatch.selector ^
        IMultiTrustCredentialCore.updateMetric.selector ^
        IMultiTrustCredentialCore.updateMetricBatch.selector ^
        IMultiTrustCredentialCore.revokeMetric.selector ^
        IMultiTrustCredentialCore.slash.selector ^
        IMultiTrustCredentialCore.getMetric.selector ^
        IMultiTrustCredentialCore.tokenIdOf.selector;

    bytes4 private constant _IID_MTC_ZK = IMultiTrustCredentialZK.proveMetric.selector;
    bytes4 private constant _IID_MTC_ZKEX = IMultiTrustCredentialZKEx.provePredicate.selector;
    
    // Roles

    /// @notice Role authorized to slash metric values.
    bytes32 public constant SLASHER_ROLE = keccak256("SLASHER_ROLE");

    // Data

    /// @dev Stored metric state for a `(tokenId, metricId)` pair.
    /// `value` is the numeric payload, `leafFull` is the anchor/commitment, `timestamp` tracks the latest write, and `expiresAt` is optional.
    struct Metric { uint32 value; uint256 leafFull; uint32 timestamp; uint32 expiresAt; }

    /// @dev Input for a single mint. `uri` is written as tokenURI on first mint for the holder.
    struct MetricInput  { bytes32 metricId; uint32 value; uint256 leafFull; string uri; uint32 expiresAt; }

    /// @dev Input for a single metric update.
    struct MetricUpdate { bytes32 metricId; uint32 newValue; uint256 leafFull; uint32 expiresAt; }

    /// @dev Batch mint item; creates the token if absent and sets tokenURI on first write.
    struct MintItem { address to; bytes32 metricId; uint32 value; uint256 leafFull; string uri; uint32 expiresAt; }

    /// @dev Batch update item for an existing token.
    struct UpdateItem { uint256 tokenId; bytes32 metricId; uint32 newValue; uint256 leafFull; uint32 expiresAt; }

    /// @dev tokenId => (metricId => Metric)
    mapping(uint256 => mapping(bytes32 => Metric)) private _metrics;

    /// @notice Per-metric freeze flag for compare-mask updates.
    /// @dev When true, writers cannot change the compare operator mask via `setCompareMask`.
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

    /// @notice metricId => predicateType => allowed flag (ZKEx).
    mapping(bytes32 => mapping(bytes32 => bool)) public predicateAllowed;

    /// @dev Predicate verification profile used by ZKEx predicates.
    /// It defines the verifier address, expected signal layout, optional epoch enforcement, and whether the base compare mask must be zero.
    struct PredicateProfile {
        address verifier;
        uint8 signalsLen;
        uint8 anchorIndex;
        uint8 addrIndex;
        uint8 epochIndex;
        bool epochCheck;
        bool requireMaskZero;
    }

    /// @notice metricId => predicateType => predicate profile (ZKEx).
    mapping(bytes32 => mapping(bytes32 => PredicateProfile)) public predicateProfile;

    /// @notice metricId => predicateType => current epoch/version for replay/freshness checks.
    mapping(bytes32 => mapping(bytes32 => uint256)) public predicateEpoch;

    /// @dev tokenId => metricId => revoked flag
    mapping(uint256 => mapping(bytes32 => bool)) private _revoked;

    uint8 internal constant _MASK_ALLOWED = uint8(CompareMask.GT | CompareMask.LT | CompareMask.EQ);

    // ZK

    /// @notice External verifier contract for zk proof checks.
    IVerifier public verifier;

    // Predicate identifiers for IMultiTrustCredentialZKEx.
    bytes32 public constant PREDICATE_ALLOWLIST = keccak256("ALLOWLIST");
    bytes32 public constant PREDICATE_RANGE = keccak256("RANGE");
    bytes32 public constant PREDICATE_DELTA = keccak256("DELTA");

    // Events
    event MetricRegistered(bytes32 indexed id, string label, bytes32 role, uint8 mask);
    event MetricUpdated(uint256 indexed tokenId, bytes32 indexed metricId, uint32 newValue, uint256 leafFull);
    event MetricRevoked(uint256 indexed tokenId, bytes32 indexed metricId, uint32 prevValue, uint256 prevLeaf);
    event Slash(uint256 indexed tokenId, bytes32 indexed metricId, uint32 penalty);
    event CompareMaskChanged(bytes32 indexed id, uint8 oldMask, uint8 newMask, address indexed editor);
    event VerifierSet(address verifier);
    event MaskFrozenSet(bytes32 id, bool frozen);
    event PredicateAllowedChanged(bytes32 indexed metricId, bytes32 indexed predicateType, bool allowed, address indexed editor);
    event PredicateProfileChanged(bytes32 indexed metricId, bytes32 indexed predicateType, address verifier, uint8 signalsLen, uint8 anchorIndex, uint8 addrIndex, uint8 epochIndex, bool epochCheck, bool requireMaskZero, address indexed editor);
    event PredicateEpochChanged(bytes32 indexed metricId, bytes32 indexed predicateType, uint256 epoch, address indexed editor);
    // Initialization

    /// @notice Disable initializers for the implementation contract (UUPS pattern).
    constructor() { _disableInitializers(); }

    /// @notice Initialize the credential system.
    /// @param admin Admin address that receives hazBase shared roles.
    /// @param forwarders Trusted ERC-2771 forwarders for meta-transactions.
    /// @dev Sets the token name and symbol to `MultiTrust Credential` / `MTC`.
    function initialize(address admin, address[] calldata forwarders) external initializer {
        __ERC721_init("MultiTrust Credential", "MTC");
        __Pausable_init();
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();
        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);
    }

    // Registry

    /// @notice Register a new metric type.
    /// @param id Unique metric id.
    /// @param label Human-readable UI label.
    /// @param roleName Writer role required to mint or update this metric.
    /// @param commitment Whether the metric should use commitment-only semantics.
    /// @param mask Allowed comparison operator bitmask.
    /// @dev Emits `MetricRegistered` and rejects duplicate metric ids.
    /// @custom:reverts MTC: metric exists if the id was already registered
    /// @custom:reverts bad mask if unsupported compare bits are set
    /// @custom:reverts MTC: empty label if the label is empty
    /// @custom:reverts empty writer role if `roleName == 0x0`
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
        require((mask & ~_MASK_ALLOWED) == 0, "bad mask");
        require(bytes(label).length > 0, "MTC: empty label");

        metricRole[id]         = roleName;
        metricLabel[id]        = label;
        isCommitmentMetric[id] = commitment;
        compareMask[id]        = mask;
        emit MetricRegistered(id, label, roleName, mask);
    }

    /// @notice Freeze or unfreeze compare-mask updates for a metric.
    /// @param id Metric id to toggle the freeze flag for.
    /// @param frozen Whether `setCompareMask` should be blocked for this metric.
    /// @dev ADMIN_ROLE control used to stabilize policy during sensitive periods.
    function setMaskFrozen(bytes32 id, bool frozen) external onlyRole(ADMIN_ROLE) {
        _assertRegistered(id);
        maskFrozen[id] = frozen;
        emit MaskFrozenSet(id, frozen);
    }

    /// @notice Allow or disallow a predicate type for a metric.
    /// @param metricId Metric id.
    /// @param predicateType Predicate identifier such as ALLOWLIST, RANGE, or DELTA.
    /// @param allowed Whether the predicate should be accepted by `provePredicate`.
    function setPredicateAllowed(bytes32 metricId, bytes32 predicateType, bool allowed) external onlyRole(ADMIN_ROLE) {
        _assertRegistered(metricId);
        predicateAllowed[metricId][predicateType] = allowed;
        emit PredicateAllowedChanged(metricId, predicateType, allowed, _msgSender());
    }

    /// @notice Update the allowed comparison mask for a metric.
    /// @param id Metric id.
    /// @param mask New comparison mask.
    /// @dev The caller must hold the metric writer role and the metric must not be frozen.
    /// @custom:reverts metric unregistered if the metric is not registered
    /// @custom:reverts role if the caller lacks the metric writer role
    /// @custom:reverts bad mask if unsupported compare bits are set
    /// @custom:reverts mask frozen if admin has frozen updates for this metric
    function setCompareMask(bytes32 id, uint8 mask) external whenNotPaused {
        _assertRegistered(id);
        require(!maskFrozen[id], "mask frozen");
        require(hasRole(metricRole[id], _msgSender()), "role");
        require((mask & ~_MASK_ALLOWED) == 0, "bad mask");

        uint8 old = compareMask[id];
        if (old == mask) return;

        compareMask[id] = mask;
        emit CompareMaskChanged(id, old, mask, _msgSender());
    }

    /// @notice Ensure that a metric id is registered before continuing.
    /// @param id Metric id.
    /// @custom:reverts metric unregistered if not registered
    function _assertRegistered(bytes32 id) internal view {
        require(metricRole[id] != bytes32(0), "metric unregistered");
    }

    // Mint

    /// @notice Mint a credential token for `to` and set an initial metric.
    /// @param to Recipient address. `tokenId` is derived as `uint256(uint160(to))`.
    /// @param data Metric input payload.
    /// @dev The token must not already exist. Commitment metrics require `value == 0`.
    /// @custom:reverts metric unregistered if the metric id is not registered
    /// @custom:reverts role if the caller lacks the writer role
    /// @custom:reverts already minted if the token already exists for `to`
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
        _metrics[tokenId][data.metricId] = Metric({ value: data.value, leafFull: data.leafFull, timestamp: uint32(block.timestamp), expiresAt: data.expiresAt });
        _revoked[tokenId][data.metricId] = false;
        emit MetricUpdated(tokenId, data.metricId, data.value, data.leafFull);
    }

    /// @notice Batch mint and/or write metrics.
    /// @param arr Array of mint items.
    /// @dev Limited to 200 items per call for gas safety. Missing holder tokens are minted on demand.
    /// @custom:reverts too many if `arr.length > 200`
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
                timestamp: uint32(block.timestamp),
                expiresAt: uint32(it.expiresAt)
            });
            _revoked[tokenId][it.metricId] = false;
            emit MetricUpdated(tokenId, it.metricId, it.value, it.leafFull);
        }
    }

    // Update

    /// @notice Update a metric for an existing token.
    /// @param tokenId Credential token id derived from the holder address.
    /// @param upd Metric update payload.
    /// @dev Requires the metric writer role and an existing holder token.
    /// @custom:reverts metric unregistered if the metric id is not registered
    /// @custom:reverts role if the caller lacks the writer role
    /// @custom:reverts token absent if the token does not exist
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
            timestamp: uint32(block.timestamp),
            expiresAt: uint32(upd.expiresAt)
        });
        _revoked[tokenId][upd.metricId] = false;
        emit MetricUpdated(tokenId, upd.metricId, upd.newValue, upd.leafFull);
    }

    /// @notice Batch update metrics.
    /// @param arr Array of update items.
    /// @dev Length is limited to 200 per call. Each item enforces registration, role, and token existence checks.
    /// @custom:reverts too many if `arr.length > 200`
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
                timestamp: uint32(block.timestamp),
                expiresAt: uint32(it.expiresAt)
            });
            _revoked[it.tokenId][it.metricId] = false;
            emit MetricUpdated(it.tokenId, it.metricId, it.newValue, it.leafFull);
        }
    }

    /// @notice Revoke a metric by zeroing both its numeric value and anchor commitment.
    /// @param tokenId Credential token id derived from the holder address.
    /// @param metricId Metric id to revoke.
    /// @dev Requires the metric writer role and emits `MetricRevoked` with the previous values.
    /// @custom:reverts metric unregistered if the metric id has not been registered
    /// @custom:reverts role if the caller lacks the metric writer role
    /// @custom:reverts token absent if the holder token does not exist
    /// @custom:reverts not issued if neither value nor commitment had been set
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

        _revoked[tokenId][metricId] = true;
        emit MetricRevoked(tokenId, metricId, prevValue, prevLeaf);
    }

    // ZK verification

    /// @notice Update the Groth16 verifier used for base metric proofs.
    /// @param _verifier New verifier contract address.
    function updateVerifier(address _verifier) external onlyRole(ADMIN_ROLE) whenNotPaused {
        verifier = IVerifier(_verifier);
        emit VerifierSet(_verifier);
    }

    /// @notice Verify a ZK proof for a given metric of a token.
    /// @param tokenId Credential token id derived from the holder address.
    /// @param metricId Metric type id.
    /// @param a Groth16 proof element `a`.
    /// @param b Groth16 proof element `b`.
    /// @param c Groth16 proof element `c`.
    /// @param pubSignals Public inputs for the metric circuit, including mode, anchor root, nullifier, bound holder address, threshold, and leaf.
    /// @return ok True if the verifier accepts the proof.
    /// @dev Enforces address binding, anchor equality, and compare-mask permissions before calling the external verifier.
    /// @custom:reverts anchor mism if `pubSignals[1] != stored leafFull`
    /// @custom:reverts addr mism if the bound holder address is not the token owner
    /// @custom:reverts tokenId mism if `tokenId != uint256(uint160(holder))`
    /// @custom:reverts bad mode if unsupported compare bits are set
    /// @custom:reverts not KYC metric if `mode == 0` but `compareMask != 0`
    /// @custom:reverts op not allowed if the metric compare mask does not include the requested mode
    /// @custom:reverts proof fail if the verifier rejects the proof
    function proveMetric(
        uint256 tokenId,
        bytes32 metricId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata pubSignals
    ) external view whenNotPaused returns (bool ok) {
        require(address(verifier) != address(0), "need verifier");
        _assertRegistered(metricId);

        // Common binding checks (revoked/expiry/addr/tokenId/anchor).
        _checkZKContext(tokenId, metricId, address(uint160(pubSignals[3])), pubSignals[1]);
        
        uint8 mode = uint8(pubSignals[0]);
        require((mode & ~uint8(CompareMask.ALL)) == 0, "bad mode");

        uint8 mask = compareMask[metricId];

        if (mode == 0) {
            require(mask == 0, "not KYC metric");
        } else {
            require((mask & mode) == mode, "op not allowed");
        }

        ok = verifier.verifyProof(a, b, c, pubSignals);
        require(ok, "proof fail");
    }

    /// @notice Return true when a predicate signal length is supported by the verifier adapters.
    /// @param n Candidate public signal length.
    function _isSupportedSignalsLen(uint8 n) internal pure returns (bool) {
        return (n == 6 || n == 8 || n == 9 || n == 10);
    }

    /// @notice Configure a predicate verification profile for a metric.
    /// @param metricId Metric id.
    /// @param predicateType Predicate identifier such as ALLOWLIST, RANGE, or DELTA.
    /// @param predVerifier Verifier contract for this predicate profile.
    /// @param signalsLen Expected number of public signals.
    /// @param anchorIndex Index of the anchor/root signal.
    /// @param addrIndex Index of the bound holder address signal.
    /// @param epochIndex Index of the epoch signal when `epochCheck` is enabled.
    /// @param epochCheck Whether predicate proofs must match the configured epoch.
    /// @param requireMaskZero Whether the base metric compare mask must be zero.
    function setPredicateProfile(
        bytes32 metricId,
        bytes32 predicateType,
        address predVerifier,
        uint8 signalsLen,
        uint8 anchorIndex,
        uint8 addrIndex,
        uint8 epochIndex,
        bool epochCheck,
        bool requireMaskZero
    ) external onlyRole(ADMIN_ROLE) {
        _assertRegistered(metricId);
        require(predVerifier != address(0), "need verifier");
        require(_isSupportedSignalsLen(signalsLen), "unsupported signalsLen");
        require(predVerifier.code.length > 0, "verifier not contract");
        require(anchorIndex < signalsLen, "bad anchorIndex");
        require(addrIndex < signalsLen, "bad addrIndex");
        if (epochCheck) require(epochIndex < signalsLen, "bad epochIndex");

        // Safety rails for common predicates
        if (predicateType == PREDICATE_DELTA) {
            require(epochCheck, "delta needs epochCheck");
        }

        predicateProfile[metricId][predicateType] = PredicateProfile({
            verifier: predVerifier,
            signalsLen: signalsLen,
            anchorIndex: anchorIndex,
            addrIndex: addrIndex,
            epochIndex: epochIndex,
            epochCheck: epochCheck,
            requireMaskZero: requireMaskZero
        });

        emit PredicateProfileChanged(
            metricId,
            predicateType,
            predVerifier,
            signalsLen,
            anchorIndex,
            addrIndex,
            epochIndex,
            epochCheck,
            requireMaskZero,
            _msgSender()
        );
    }

    /// @notice Update the epoch/version used by an epoch-checked predicate profile.
    /// @param metricId Metric id.
    /// @param predicateType Predicate identifier.
    /// @param epoch New epoch value that proofs must carry.
    function setPredicateEpoch(bytes32 metricId, bytes32 predicateType, uint256 epoch) external onlyRole(ADMIN_ROLE) {
        _assertRegistered(metricId);
        PredicateProfile memory p = predicateProfile[metricId][predicateType];
        require(p.verifier != address(0), "predicate profile unset");
        require(p.epochCheck, "epochCheck disabled");
        predicateEpoch[metricId][predicateType] = epoch;
        emit PredicateEpochChanged(metricId, predicateType, epoch, _msgSender());
    }

    /// @notice Verify a predicate proof using the configured ZKEx-style predicate profile.
    /// @param tokenId Credential token id.
    /// @param metricId Metric id.
    /// @param predicateType Predicate identifier.
    /// @param proof ABI-encoded Groth16 proof bytes.
    /// @param publicSignals Public inputs for the predicate circuit.
    function provePredicate(
        uint256 tokenId,
        bytes32 metricId,
        bytes32 predicateType,
        bytes calldata proof,
        uint256[] calldata publicSignals
    ) external view whenNotPaused returns (bool ok) {
        // Decode Groth16 proof bytes as abi.encode(a,b,c).
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) =
            abi.decode(proof, (uint256[2], uint256[2][2], uint256[2]));

        // Copy calldata publicSignals to memory once; internal core accepts memory.
        uint256[] memory ps = new uint256[](publicSignals.length);
        for (uint256 i = 0; i < publicSignals.length; i++) {
            ps[i] = publicSignals[i];
        }

        ok = _provePredicateCore(tokenId, metricId, predicateType, a, b, c, ps);
    }

    /// @notice Backward-compatible allowlist wrapper. Prefer `provePredicate(..., PREDICATE_ALLOWLIST, ...)`.
    function proveGroupMetric(
        uint256 tokenId,
        bytes32 metricId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[6] calldata pubSignals
    ) external view whenNotPaused returns (bool ok) {
        _assertRegistered(metricId);
        // Backward-compatible wrapper. Prefer provePredicate() with PREDICATE_ALLOWLIST.
        uint256[] memory ps = new uint256[](6);
        for (uint256 i = 0; i < 6; i++) {
            ps[i] = pubSignals[i];
        }
        ok = _provePredicateCore(tokenId, metricId, PREDICATE_ALLOWLIST, a, b, c, ps);
    }

    /// @notice Shared ZK binding checks used by both base metric proofs and predicate proofs.
    /// @param tokenId Credential token id.
    /// @param metricId Metric id.
    /// @param holder Address recovered from the proof public signals.
    /// @param anchor Anchor/root recovered from the proof public signals.
    function _checkZKContext(
        uint256 tokenId,
        bytes32 metricId,
        address holder,
        uint256 anchor
    ) internal view {
        // shared binding checks for baseline and predicates.
        require(!_revoked[tokenId][metricId], "revoked");
        require(tokenId == uint256(uint160(holder)), "tokenId mism");
        require(ownerOf(tokenId) == holder, "addr mism");
        require(anchor == _metrics[tokenId][metricId].leafFull, "anchor mism");
        uint32 exp = _metrics[tokenId][metricId].expiresAt;
        if (exp != 0) {
            require(block.timestamp <= exp, "metric expired");
        }
    }

    /// @notice Shared predicate proof verification core.
    /// @param tokenId Credential token id.
    /// @param metricId Metric id.
    /// @param predicateType Predicate identifier.
    /// @param a Groth16 proof element `a`.
    /// @param b Groth16 proof element `b`.
    /// @param c Groth16 proof element `c`.
    /// @param publicSignals Predicate public inputs copied into memory.
    function _provePredicateCore(
        uint256 tokenId,
        bytes32 metricId,
        bytes32 predicateType,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory publicSignals
    ) internal view returns (bool ok) {
        _assertRegistered(metricId);
        require(predicateAllowed[metricId][predicateType], "predicate not allowed");
        require(!_revoked[tokenId][metricId], "revoked");

        PredicateProfile memory p = predicateProfile[metricId][predicateType];
        require(p.verifier != address(0), "predicate profile unset");

        require(publicSignals.length == p.signalsLen, "bad publicSignals");
        if (p.requireMaskZero) {
            require(compareMask[metricId] == 0, "mask not zero");
        }

        address holder = address(uint160(publicSignals[p.addrIndex]));
        _checkZKContext(tokenId, metricId, holder, publicSignals[p.anchorIndex]);

        if (p.epochCheck) {
            require(publicSignals[p.epochIndex] == predicateEpoch[metricId][predicateType], "bad epoch");
        }

        ok = _verifyPredicateProofMemory(p.verifier, a, b, c, publicSignals);
        require(ok, "proof fail");
    }

    /// @notice Dispatch predicate verification to the verifier ABI that matches `publicSignals.length`.
    /// @param predVerifier Verifier contract address.
    /// @param a Groth16 proof element `a`.
    /// @param b Groth16 proof element `b`.
    /// @param c Groth16 proof element `c`.
    /// @param publicSignals Predicate public inputs copied into memory.
    function _verifyPredicateProofMemory(
        address predVerifier,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[] memory publicSignals
    ) internal view returns (bool ok) {
        // verifier ABIs commonly use fixed-size arrays; branch by length.
        if (publicSignals.length == 6) {
            uint256[6] memory ps6;
            for (uint256 i = 0; i < 6; i++) ps6[i] = publicSignals[i];
            ok = IVerifier(predVerifier).verifyProof(a, b, c, ps6);
            return ok;
        }
        if (publicSignals.length == 8) {
            uint256[8] memory ps8;
            for (uint256 i = 0; i < 8; i++) ps8[i] = publicSignals[i];
            ok = IVerifier8(predVerifier).verifyProof(a, b, c, ps8);
            return ok;
        }
        if (publicSignals.length == 9) {
            uint256[9] memory ps9;
            for (uint256 i = 0; i < 9; i++) ps9[i] = publicSignals[i];
            ok = IVerifier9(predVerifier).verifyProof(a, b, c, ps9);
            return ok;
        }
        if (publicSignals.length == 10) {
            uint256[10] memory ps10;
            for (uint256 i = 0; i < 10; i++) ps10[i] = publicSignals[i];
            ok = IVerifier10(predVerifier).verifyProof(a, b, c, ps10);
            return ok;
        }
        revert("unsupported signalsLen");
    }

    /// @notice Reduce a metric's numeric value for an offender.
    /// @param offender Address whose token is targeted.
    /// @param metricId Metric type to slash.
    /// @param penalty Amount to subtract from the current value.
    /// @dev Caller must hold SLASHER_ROLE. Updates the metric timestamp and emits `Slash`.
    /// @custom:reverts 0 if `penalty == 0`
    /// @custom:reverts underflow if the current value is smaller than `penalty`
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
        require(!_revoked[tokenId][metricId], "revoked");

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

    /// @notice Return whether this contract supports an ERC165 interface id.
    /// @param id Interface id.
    /// @return bool Whether the interface is supported.
    function supportsInterface(bytes4 id)
        public view override(AccessControlEnumerableUpgradeable, ERC721URIStorageUpgradeable)
        returns (bool)
    {
        return
            id == _IID_MTC_CORE ||
            id == _IID_MTC_ZK ||
            id == _IID_MTC_ZKEX ||
            super.supportsInterface(id);
    }

    // Pause and upgrade

    /// @notice Pause state-changing entrypoints; only PAUSER_ROLE.
    function pause() external onlyRole(PAUSER_ROLE) { _pause(); }

    /// @notice Unpause state-changing entrypoints; only PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) { _unpause(); }

    // meta-tx ---------------------------------------------------------------

    /// @dev ERC-2771 meta-tx sender override.
    function _msgSender() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(address){return ERC2771ContextUpgradeable._msgSender();}

    /// @dev ERC-2771 meta-tx data override.
    function _msgData() internal view override(ContextUpgradeable,ERC2771ContextUpgradeable) returns(bytes calldata){return ERC2771ContextUpgradeable._msgData();}

    /// @notice Authorize a UUPS upgrade; only ADMIN_ROLE.
    function _authorizeUpgrade(address) internal override onlyRole(ADMIN_ROLE) {}
}

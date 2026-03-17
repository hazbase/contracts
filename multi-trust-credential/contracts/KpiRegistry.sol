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

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";

import "./extensions/RolesCommon.sol";
import "./external/oz/metax/ERC2771ContextUpgradeable.sol";
import "./MultiTrustCredential.sol";

/**
 *  @title KpiRegistry — Developer & Auditor Commented Version
 *
 *  @notice
 *  - Purpose: Project-oriented **KPI registry** that defines KPI metadata (label, decimals,
 *    compare mask, threshold, commitment flag) and **pushes KPI values** to the
 *    `MultiTrustCredential` (MTC) contract as metric updates. Emits threshold-hit events
 *    when numeric KPIs satisfy their comparison rule. Also records update epochs.
 *
 *  - Data model:
 *      * `Meta` describes a KPI type keyed by `metricId` (derived from `{projectId,label}`).
 *      * For each KPI, `epochs[metricId]` tracks timestamps of updates (append-only).
 *      * `projectKpis[projectId]` lists KPI metricIds belonging to that project.
 *      * Values themselves are **stored in MTC** (this registry delegates to `mtc.updateMetric`).
 *
 *  - Roles & Access:
 *      * `ADMIN_ROLE` — registers KPIs (metadata) and configures registry.
 *      * `ORACLE_ROLE` — pushes KPI values (`pushKpiValue`) to MTC.
 *      * `PAUSER_ROLE` — pause/unpause.
 *
 *  - Security / Audit Notes:
 *      * Threshold checks are performed **after** a successful push to MTC.
 *      * For commitment KPIs (`commitment=true`), threshold evaluation is **skipped** (event is not emitted).
 *      * Comparison mask uses `CompareMask` bits defined in the MTC compilation unit (GTE=1, LTE=2, EQ=4).
 *      * UUPS upgrade is gated by `ADMIN_ROLE`. ERC-2771 meta-tx supported via `_msgSender/_msgData`.
 */

contract KpiRegistry is
    Initializable,
    UUPSUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    ERC2771ContextUpgradeable,
    RolesCommonUpgradeable
{
    // Roles

    /// @notice Addresses permitted to push KPI values to MTC.
    bytes32 public constant ORACLE_ROLE = keccak256("ORACLE_ROLE");

    // Structs

    /// @notice KPI metadata stored by the registry.
    /// `projectId` groups KPIs by project, `label` helps derive `metricId`, and the remaining fields describe display and threshold behavior.
    struct Meta {
        bytes32 projectId;
        string  label;
        uint8   decimals;
        uint8   compareMask;
        uint256 threshold;
        bool    commitment;
    }

    // Storage

    /// @dev KPI registry by metricId (derived from `{projectId,label}`).
    mapping(bytes32 => Meta) private kpis;

    /// @dev Update timestamps per KPI (append-only).
    mapping(bytes32 => uint256[]) private epochs;

    /// @dev KPI list per project.
    mapping(bytes32 => bytes32[]) private projectKpis;

    /// @notice External credential contract where KPI values are written.
    MultiTrustCredential public mtc;

    // Events

    /// @notice Emitted when a KPI is registered.
    event MetricRegistered(bytes32 indexed metricId, bytes32 indexed projectId, string label);

    /// @notice Emitted after an oracle pushes a KPI value to MTC.
    event MetricUpdated(bytes32 indexed metricId, uint256 value, uint256 ts);

    /// @notice Emitted if a **numeric** KPI satisfies its comparison rule against `threshold`.
    event ThresholdHit(bytes32 indexed metricId, uint256 value, uint256 ts);

    // Initializer

    /// @notice Initialize the KPI registry.
    /// @param admin Admin address granted hazBase admin roles.
    /// @param mtcAddress Deployed `MultiTrustCredential` contract address.
    /// @param forwarders Trusted ERC-2771 forwarders for meta-transactions.
    /// @dev Calls initializers for reentrancy guard, pause control, UUPS, ERC-2771, and shared roles.
    /// @custom:reverts zero addr if any of {admin, mtcAddress} is zero
    function initialize(address admin, address mtcAddress, address[] calldata forwarders) external initializer {
        require(admin != address(0) && mtcAddress != address(0), "zero addr");
        __ReentrancyGuard_init();
        __Pausable_init();
        __UUPSUpgradeable_init();

        __ERC2771Context_init(forwarders);
        __RolesCommon_init(admin);

        mtc = MultiTrustCredential(mtcAddress);
    }

    // KPI registration

    /// @notice Register a new KPI metadata entry and mirror its metric in MTC.
    /// @param projectId Project identifier that owns this KPI.
    /// @param label Human-readable KPI label used together with `projectId` to derive `metricId`.
    /// @param roleName MTC writer role name that will be required for updates.
    /// @param decimals Display decimals; must be non-zero for a registered KPI.
    /// @param compareMask Allowed comparison mask (0..7, bitwise OR of CompareMask).
    /// @param threshold Numeric threshold for `ThresholdHit` when this KPI is not commitment-based.
    /// @param commitment Whether the KPI should be treated as a commitment/hash metric.
    /// @return metricId Deterministic id `keccak256(abi.encodePacked(projectId, label))`.
    /// @dev Also registers the mirrored metric inside MTC via `mtc.registerMetric(...)`.
    /// @custom:reverts label empty if `label.length == 0`
    /// @custom:reverts bad mask if `compareMask > 7`
    /// @custom:reverts decimals=0 if `decimals == 0`
    /// @custom:reverts exists if KPI already registered
    function registerKpi(
        bytes32 projectId,
        string  calldata label,
        bytes32 roleName,
        uint8   decimals,
        uint8   compareMask,
        uint256 threshold,
        bool    commitment
    ) external whenNotPaused onlyRole(ADMIN_ROLE) returns (bytes32 metricId) {
        require(bytes(label).length != 0, "label empty");
        require(compareMask <= 7, "bad mask");
        require(decimals > 0, "decimals=0");

        metricId = keccak256(abi.encodePacked(projectId, label));
        require(
            kpis[metricId].decimals == 0 &&
            bytes(kpis[metricId].label).length == 0,
            "exists"
        );

        kpis[metricId] = Meta({
            projectId   : projectId,
            label       : label,
            decimals    : decimals,
            compareMask : compareMask,
            threshold   : threshold,
            commitment  : commitment
        });

        projectKpis[projectId].push(metricId);

        // Mirror registration in MTC (will enforce writer role on writes)
        mtc.registerMetric(metricId, label, roleName, commitment, compareMask);

        emit MetricRegistered(metricId, projectId, label);
    }

    // KPI value updates

    /// @notice Push a KPI value into MTC and record an epoch timestamp.
    /// @param tokenId Credential token id in MTC to update.
    /// @param upd MTC `MetricUpdate` payload that carries the new metric value.
    /// @dev Only ORACLE_ROLE may push values. Numeric KPIs emit `ThresholdHit` when they satisfy the configured comparison rule.
    /// @custom:reverts not registered if KPI meta not found (decimals == 0)
    function pushKpiValue(
        uint256 tokenId,
        MultiTrustCredential.MetricUpdate calldata upd
    ) external whenNotPaused onlyRole(ORACLE_ROLE) nonReentrant {
        Meta memory meta = kpis[upd.metricId];
        require(meta.decimals > 0, "not registered");

        mtc.updateMetric(tokenId, upd);

        epochs[upd.metricId].push(block.timestamp);
        emit MetricUpdated(upd.metricId, upd.newValue, block.timestamp);

        if (!meta.commitment && _compare(meta.compareMask, upd.newValue, meta.threshold)) {
            emit ThresholdHit(upd.metricId, upd.newValue, block.timestamp);
        }
    }

    // Views

    /// @notice Read KPI metadata by `metricId`.
    /// @param metricId KPI id derived in `registerKpi`.
    /// @return Meta KPI metadata struct.
    function kpiMeta(bytes32 metricId) external view returns (Meta memory) {
        return kpis[metricId];
    }

    /// @notice Get the latest update timestamp for a KPI.
    /// @param metricId KPI id.
    /// @return uint256 Latest epoch timestamp, or zero when the KPI has never been updated.
    function latestTimestamp(bytes32 metricId) external view returns (uint256) {
        uint256[] storage arr = epochs[metricId];
        if (arr.length == 0) return 0;
        return arr[arr.length - 1];
    }

    /// @notice List KPI ids registered under a project.
    /// @param projectId Project identifier.
    /// @return bytes32[] Array of KPI metric ids, which may be empty.
    function listProjectKpis(bytes32 projectId) external view returns (bytes32[] memory) {
        return projectKpis[projectId];
    }

    // Internal helpers

    /// @notice Evaluate a comparison mask against `(v, th)`.
    /// @param mask Comparison mask encoded as a bitwise OR of CompareMask values.
    /// @param v Candidate value.
    /// @param th Threshold value.
    /// @return bool True when every enabled comparison relation passes.
    /// @dev CompareMask constants are imported from the MTC contract.
    function _compare(uint8 mask, uint256 v, uint256 th) internal pure returns (bool) {
        bool ok = true;
        if (mask & CompareMask.GT != 0) ok = ok && (v > th);
        if (mask & CompareMask.LT != 0) ok = ok && (v < th);
        if (mask & CompareMask.EQ  != 0) ok = ok && (v == th);
        return ok;
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

    /// @dev Storage gap reserved for future upgrades.
    uint256[43] private __gap;
}

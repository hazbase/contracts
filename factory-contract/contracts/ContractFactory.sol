// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

//   @author IndieSquare
//    __  __     ______     ______     ______     ______     ______     ______
//   /\ \_\ \   /\  __ \   /\___  \   /\  == \   /\  __ \   /\  ___\   /\  ___\
//   \ \  __ \  \ \  __ \  \/_/  /__  \ \  __<   \ \  __ \  \ \___  \  \ \  __\
//    \ \_\ \_\  \ \_\ \_\   /\_____\  \ \_____\  \ \_\ \_\  \/\_____\  \ \_____\
//     \/_/\/_/   \/_/\/_/   \/_____/   \/_____/   \/_/\/_/   \/_____/   \/_____/
//
//   https://hazbase.com

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 *  @title ContractFactory
 *
 *  @notice
 *  - Purpose: Generic factory that lets *namespaced owners* (implementation owners)
 *             publish versioned implementation addresses, and lets deployers clone
 *             (EIP-1167 minimal proxy) a chosen version and run its initializer.
 *  - Namespacing & Versions:
 *      * Each (implementationOwner, contractType) pair has an independent version history.
 *      * `setImplementation()` appends a new version number (starting at 1).
 *      * Any deployer can deploy a clone for any published namespace/version.
 *  - Deployment:
 *      * Proxies are created via `Clones.clone()` (EIP-1167 minimal proxies).
 *      * The factory immediately calls the clone with `initData` (initializer call-data).
 *      * On success, the proxy is recorded under the caller’s `deployedContracts`.
 *  - Access:
 *      * `ADMIN_ROLE` can grant/revoke `DEPLOYER_ROLE` and also set implementations.
 *      * `DEPLOYER_ROLE` can also set implementations (in addition to deploying).
 *      * Anyone can deploy using a published namespace; access control for the target
 *        contract is the target’s responsibility (e.g., initial admin param).
 *  - Security / Audit Notes:
 *      * The factory does not validate `impl` code contents; use trusted addresses.
 *      * `initData` is arbitrary call data executed on the freshly cloned proxy;
 *        ensure it points to a non-reentrant initializer (factory is `nonReentrant`).
 *      * Reentrancy: `deploy*` methods are guarded with `nonReentrant`.
 *      * Event trails: version additions and deployments are emitted for traceability.
 *      * Upgradability: this factory is non-upgradeable and holds minimal state.
 */
 
contract ContractFactory is AccessControl, ReentrancyGuard {
    using Clones for address;

    /// @notice Role ids
    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant DEPLOYER_ROLE = keccak256("DEPLOYER_ROLE");

    /**
     * @dev Versioned implementation metadata stored per (owner, contractType).
     * - `version`   : monotonically increasing (starts at 1).
     * - `impl`      : implementation address (EIP-1167 target).
     * - `timestamp` : block timestamp when the version was published.
     */
    struct Implementation {
        uint32   version;
        address  impl;
        uint256  timestamp;
    }

    /// @dev implementationHistory[owner][contractType] → array of versions
    mapping(address => mapping(bytes32 => Implementation[]))
        private implementationHistory;

    /// @notice Deployments made by a given deployer address
    mapping(address => address[]) public deployedContracts;

    /// @notice Emitted when a new implementation version is added to an owner/type namespace
    event ImplementationVersionAdded(
        address indexed owner,
        bytes32 indexed contractType,
        uint32  indexed version,
        address implementation
    );

    /// @notice Emitted when a clone proxy is deployed
    event ContractDeployed(
        address indexed implementationOwner,
        bytes32 indexed contractType,
        address indexed proxy,
        address deployer
    );

    /**
     * @notice Initialize roles.
     * @param admin Address that receives DEFAULT_ADMIN_ROLE, ADMIN_ROLE, and DEPLOYER_ROLE.
     *
     * @dev
     * - DEFAULT_ADMIN_ROLE administers itself and ADMIN_ROLE.
     * - ADMIN_ROLE administers DEPLOYER_ROLE.
     */
    constructor(address admin) {
        // DEFAULT_ADMIN_ROLE is its own admin; ADMIN_ROLE governed by DEFAULT_ADMIN_ROLE
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
        _grantRole(DEPLOYER_ROLE, admin);

        _setRoleAdmin(ADMIN_ROLE, DEFAULT_ADMIN_ROLE);
        // DEPLOYER_ROLE governed by ADMIN_ROLE
        _setRoleAdmin(DEPLOYER_ROLE, ADMIN_ROLE);
    }

    /**
     * @notice Grant DEPLOYER_ROLE to an address.
     * @param who Address to grant.
     *
     * @dev Only callable by ADMIN_ROLE.
     */
    function grantDeployer(address who) external onlyRole(ADMIN_ROLE) {
        grantRole(DEPLOYER_ROLE, who);
    }

    /**
     * @notice Revoke DEPLOYER_ROLE from an address.
     * @param who Address to revoke.
     *
     * @dev Only callable by ADMIN_ROLE.
     */
    function revokeDeployer(address who) external onlyRole(ADMIN_ROLE) {
        revokeRole(DEPLOYER_ROLE, who);
    }

    /**
     * @notice Publish a new implementation version in the caller’s namespace.
     * @param contractType Bytes32 identifier for the contract family/type (e.g., keccak256("BondToken")).
     * @param impl         Implementation address to be used as EIP-1167 target.
     *
     * @dev
     * - Access: ADMIN_ROLE or DEPLOYER_ROLE.
     * - Effects: Appends a new version (length+1) to caller’s (owner) namespace.
     * - Emits: ImplementationVersionAdded(owner=msg.sender, contractType, version, impl).
     *
     * @custom:reverts ContractFactory: must have ADMIN or DEPLOYER role
     */
    function setImplementation(bytes32 contractType, address impl)
        external
    {
        require(
            hasRole(ADMIN_ROLE, msg.sender) ||
            hasRole(DEPLOYER_ROLE, msg.sender),
            "ContractFactory: must have ADMIN or DEPLOYER role"
        );

        Implementation[] storage hist =
            implementationHistory[msg.sender][contractType];
        uint32 newVersion = uint32(hist.length) + 1;
        hist.push(Implementation({
            version:   newVersion,
            impl:      impl,
            timestamp: block.timestamp
        }));
        emit ImplementationVersionAdded(
            msg.sender,
            contractType,
            newVersion,
            impl
        );
    }

    /**
     * @notice Read the latest implementation for an owner/type namespace.
     * @param owner         Implementation owner (namespace root).
     * @param contractType  Type key for the desired contract family.
     * @return address      Latest implementation address.
     *
     * @dev Reverts if no versions exist.
     * @custom:reverts No implementation if the history is empty
     */
    function getLatestImplementation(address owner, bytes32 contractType)
        public
        view
        returns (address)
    {
        Implementation[] storage hist =
            implementationHistory[owner][contractType];
        require(hist.length > 0, "No implementation");
        return hist[hist.length - 1].impl;
    }

    /**
     * @notice Read the implementation address and timestamp for a specific version.
     * @param owner         Implementation owner (namespace root).
     * @param contractType  Type key for the desired contract family.
     * @param version       1-based version index.
     * @return impl         Implementation address for the version.
     * @return timestamp    Publish time for that version.
     *
     * @dev Reverts if `version` is out of range.
     * @custom:reverts Invalid version if `version == 0` or `> hist.length`
     */
    function getImplementationByVersion(
        address owner,
        bytes32 contractType,
        uint32 version
    )
        public
        view
        returns (address impl, uint256 timestamp)
    {
        Implementation[] storage hist =
            implementationHistory[owner][contractType];
        require(version > 0 && version <= hist.length, "Invalid version");
        Implementation storage entry = hist[version - 1];
        return (entry.impl, entry.timestamp);
    }

    /**
     * @notice Deploy a new clone proxy using the *latest* version in an owner/type namespace.
     * @param implementationOwner  Namespace owner whose latest version will be used.
     * @param contractType         Type key within that namespace.
     * @param initData             ABI-encoded initializer call (e.g., abi.encodeWithSelector(Impl.initialize.selector, ...)).
     * @return proxy               Address of the deployed minimal proxy.
     *
     * @dev
     * - Effects:
     *   * Resolves latest `impl`, clones it via EIP-1167 `clone()`, then executes `proxy.call(initData)`.
     *   * Records the proxy under `deployedContracts[msg.sender]`.
     * - Emits: ContractDeployed(implementationOwner, contractType, proxy, deployer=msg.sender).
     *
     * @custom:reverts No implementation if none published for namespace
     * @custom:reverts Init failed       if initializer call reverts or returns (ok=false)
     */
    function deployContract(
        address implementationOwner,
        bytes32 contractType,
        bytes calldata initData
    )
        external
        nonReentrant
        returns (address proxy)
    {
        address impl = getLatestImplementation(implementationOwner, contractType);

        // Create minimal proxy clone
        proxy = impl.clone();
        // Execute initializer
        (bool ok, ) = proxy.call(initData);
        require(ok, "Init failed");

        deployedContracts[msg.sender].push(proxy);
        emit ContractDeployed(
            implementationOwner,
            contractType,
            proxy,
            msg.sender
        );
    }

    /**
     * @notice Deploy a new clone proxy using a *specific* version in an owner/type namespace.
     * @param implementationOwner  Namespace owner.
     * @param contractType         Type key within that namespace.
     * @param version              1-based version index to deploy.
     * @param initData             ABI-encoded initializer call.
     * @return proxy               Address of the deployed minimal proxy.
     *
     * @dev Same flow as `deployContract` but selects a static version.
     *
     * @custom:reverts Invalid version  if version does not exist
     * @custom:reverts Init failed       if initializer call reverts or returns (ok=false)
     */
    function deployContractByVersion(
        address implementationOwner,
        bytes32 contractType,
        uint32 version,
        bytes calldata initData
    )
        external
        nonReentrant
        returns (address proxy)
    {
        (address impl, ) =
            getImplementationByVersion(implementationOwner, contractType, version);

        proxy = impl.clone();
        (bool ok, ) = proxy.call(initData);
        require(ok, "Init failed");

        deployedContracts[msg.sender].push(proxy);
        emit ContractDeployed(
            implementationOwner,
            contractType,
            proxy,
            msg.sender
        );
    }
}

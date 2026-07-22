import fs from 'node:fs';
import type { Contract } from 'ethers';
import { ethers } from 'hardhat';

type GovernanceTarget = {
  name: string;
  address: string;
  timelockRoles: string[];
  pauseGuardRole?: string;
  legacyAdmin?: string;
  revokeLegacyRoles?: string[];
};

type GovernanceManifest = {
  schema: 'hazama-governance-migration/v1';
  timelock: string;
  pauseGuard: string;
  targets: GovernanceTarget[];
};

const accessControlAbi = [
  'function hasRole(bytes32 role,address account) view returns (bool)',
  'function grantRole(bytes32 role,address account)',
  'function revokeRole(bytes32 role,address account)',
];

const pauseGuardAbi = [
  'function isTarget(address target) view returns (bool)',
];

function includesDefaultAdminRole(values: string[] | undefined): boolean {
  return (values ?? []).some((value) => (
    value === 'DEFAULT_ADMIN_ROLE'
    || (ethers.isHexString(value, 32) && value.toLowerCase() === ethers.ZeroHash)
  ));
}

function loadManifest(): GovernanceManifest {
  const path = process.env.HAZAMA_GOVERNANCE_MANIFEST_FILE?.trim();
  if (!path) throw new Error('HAZAMA_GOVERNANCE_MANIFEST_FILE is required');
  const parsed = JSON.parse(fs.readFileSync(path, 'utf8')) as GovernanceManifest;
  if (parsed.schema !== 'hazama-governance-migration/v1') throw new Error('Unsupported governance manifest schema');
  if (!ethers.isAddress(parsed.timelock)) throw new Error('manifest.timelock must be an EVM address');
  if (!ethers.isAddress(parsed.pauseGuard)) throw new Error('manifest.pauseGuard must be an EVM address');
  if (!Array.isArray(parsed.targets) || parsed.targets.length === 0) throw new Error('manifest.targets must not be empty');
  const targetAddresses = new Set<string>();
  for (const target of parsed.targets) {
    if (!target.name?.trim()) throw new Error('Each governance target requires a name');
    if (!ethers.isAddress(target.address)) throw new Error(`Invalid target address for ${target.name}`);
    if (!Array.isArray(target.timelockRoles) || target.timelockRoles.length === 0) {
      throw new Error(`Target ${target.name} requires at least one Timelock role`);
    }
    if (!includesDefaultAdminRole(target.timelockRoles)) {
      throw new Error(`Target ${target.name} must grant DEFAULT_ADMIN_ROLE to the Timelock`);
    }
    if (!includesDefaultAdminRole(target.revokeLegacyRoles)) {
      throw new Error(`Target ${target.name} must revoke DEFAULT_ADMIN_ROLE from the legacy admin`);
    }
    if (target.legacyAdmin && !ethers.isAddress(target.legacyAdmin)) {
      throw new Error(`Invalid legacyAdmin for ${target.name}`);
    }
    const normalizedAddress = ethers.getAddress(target.address);
    if (targetAddresses.has(normalizedAddress)) throw new Error(`Duplicate governance target: ${normalizedAddress}`);
    targetAddresses.add(normalizedAddress);
  }
  return parsed;
}

function normalizeManifest(manifest: GovernanceManifest) {
  return {
    schema: manifest.schema,
    timelock: ethers.getAddress(manifest.timelock),
    pauseGuard: ethers.getAddress(manifest.pauseGuard),
    targets: manifest.targets
      .map((target) => ({
        name: target.name.trim(),
        address: ethers.getAddress(target.address),
        timelockRoles: [...new Set(target.timelockRoles)].sort(),
        pauseGuardRole: target.pauseGuardRole ?? null,
        legacyAdmin: target.legacyAdmin ? ethers.getAddress(target.legacyAdmin) : null,
        revokeLegacyRoles: [...new Set(target.revokeLegacyRoles ?? [])].sort(),
      }))
      .sort((left, right) => left.address.localeCompare(right.address)),
  };
}

async function resolveRole(targetAddress: string, value: string): Promise<string> {
  if (ethers.isHexString(value, 32)) return value;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error(`Invalid role getter: ${value}`);
  const reader = new ethers.Contract(targetAddress, [`function ${value}() view returns (bytes32)`], ethers.provider);
  return String(await reader[value]());
}

async function waitForRole(
  contract: Contract,
  role: string,
  account: string,
  expected: boolean,
) {
  const actual = Boolean(await contract.hasRole(role, account));
  if (actual !== expected) throw new Error(`Role verification failed for ${account}: expected ${expected}`);
}

async function main() {
  const manifest = loadManifest();
  const normalized = normalizeManifest(manifest);
  const manifestHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify(normalized)));
  const mode = process.env.HAZAMA_GOVERNANCE_MIGRATION_MODE?.trim() || 'audit';
  if (!['audit', 'prepare', 'finalize'].includes(mode)) {
    throw new Error('HAZAMA_GOVERNANCE_MIGRATION_MODE must be audit, prepare, or finalize');
  }

  const [signer] = await ethers.getSigners();
  if (!signer) throw new Error('No migration signer is configured');
  const signerAddress = await signer.getAddress();
  const timelockAddress = ethers.getAddress(manifest.timelock);
  const pauseGuardAddress = ethers.getAddress(manifest.pauseGuard);
  const timelockCode = await ethers.provider.getCode(timelockAddress);
  const pauseGuardCode = await ethers.provider.getCode(pauseGuardAddress);
  if (timelockCode === '0x') throw new Error('Timelock contract is not deployed');
  if (pauseGuardCode === '0x') throw new Error('Pause guard contract is not deployed');
  const pauseGuard = new ethers.Contract(pauseGuardAddress, pauseGuardAbi, ethers.provider);

  if (mode === 'finalize') {
    if (process.env.HAZAMA_GOVERNANCE_CONFIRM_MANIFEST_HASH?.toLowerCase() !== manifestHash.toLowerCase()) {
      throw new Error(`Finalize requires HAZAMA_GOVERNANCE_CONFIRM_MANIFEST_HASH=${manifestHash}`);
    }
    const operationId = process.env.HAZAMA_GOVERNANCE_PROOF_OPERATION_ID?.trim();
    if (!operationId || !ethers.isHexString(operationId, 32)) {
      throw new Error('Finalize requires a bytes32 HAZAMA_GOVERNANCE_PROOF_OPERATION_ID');
    }
    const timelock = new ethers.Contract(
      timelockAddress,
      ['function isOperationDone(bytes32 id) view returns (bool)'],
      ethers.provider,
    );
    if (!(await timelock.isOperationDone(operationId))) {
      throw new Error('The required Timelock test operation has not completed');
    }
  }

  const report = [];
  for (const target of manifest.targets) {
    const targetAddress = ethers.getAddress(target.address);
    if (await ethers.provider.getCode(targetAddress) === '0x') {
      throw new Error(`Governance target is not deployed: ${target.name} (${targetAddress})`);
    }
    const contract = new ethers.Contract(targetAddress, accessControlAbi, signer);
    const timelockRoles = await Promise.all(target.timelockRoles.map((role) => resolveRole(targetAddress, role)));
    const pauseGuardRole = target.pauseGuardRole
      ? await resolveRole(targetAddress, target.pauseGuardRole)
      : null;
    const legacyAdmin = ethers.getAddress(target.legacyAdmin ?? signerAddress);
    const revokeRoles = await Promise.all((target.revokeLegacyRoles ?? []).map((role) => resolveRole(targetAddress, role)));
    const pauseGuardTargetAllowed = pauseGuardRole
      ? Boolean(await pauseGuard.isTarget(targetAddress))
      : null;
    const transactions: Array<{
      action: 'grantRole' | 'revokeRole';
      role: string;
      account: string;
      transactionHash: string;
    }> = [];
    if (pauseGuardRole && !pauseGuardTargetAllowed) {
      throw new Error(`Pause guard does not allow target ${target.name} (${targetAddress})`);
    }

    if (mode === 'prepare') {
      for (const role of timelockRoles) {
        if (!(await contract.hasRole(role, timelockAddress))) {
          const transaction = await contract.grantRole(role, timelockAddress);
          const receipt = await transaction.wait();
          transactions.push({
            action: 'grantRole',
            role,
            account: timelockAddress,
            transactionHash: receipt?.hash ?? transaction.hash,
          });
        }
      }
      if (pauseGuardRole && !(await contract.hasRole(pauseGuardRole, pauseGuardAddress))) {
        const transaction = await contract.grantRole(pauseGuardRole, pauseGuardAddress);
        const receipt = await transaction.wait();
        transactions.push({
          action: 'grantRole',
          role: pauseGuardRole,
          account: pauseGuardAddress,
          transactionHash: receipt?.hash ?? transaction.hash,
        });
      }
    }

    if (mode !== 'audit') {
      for (const role of timelockRoles) await waitForRole(contract, role, timelockAddress, true);
      if (pauseGuardRole) await waitForRole(contract, pauseGuardRole, pauseGuardAddress, true);
    }

    if (mode === 'finalize') {
      // DEFAULT_ADMIN_ROLE must be revoked last or the signer may lose the
      // authority needed to remove its remaining operational roles.
      const orderedRevokeRoles = [...revokeRoles].sort((left, right) => {
        if (left === ethers.ZeroHash) return 1;
        if (right === ethers.ZeroHash) return -1;
        return left.localeCompare(right);
      });
      for (const role of orderedRevokeRoles) {
        if (await contract.hasRole(role, legacyAdmin)) {
          const transaction = await contract.revokeRole(role, legacyAdmin);
          const receipt = await transaction.wait();
          transactions.push({
            action: 'revokeRole',
            role,
            account: legacyAdmin,
            transactionHash: receipt?.hash ?? transaction.hash,
          });
        }
        await waitForRole(contract, role, legacyAdmin, false);
      }
    }

    report.push({
      name: target.name,
      address: targetAddress,
      timelockRoles: await Promise.all(timelockRoles.map(async (role) => ({
        role,
        granted: Boolean(await contract.hasRole(role, timelockAddress)),
      }))),
      pauseGuardRole: pauseGuardRole ? {
        role: pauseGuardRole,
        granted: Boolean(await contract.hasRole(pauseGuardRole, pauseGuardAddress)),
        targetAllowed: pauseGuardTargetAllowed,
      } : null,
      legacyRoles: await Promise.all(revokeRoles.map(async (role) => ({
        role,
        account: legacyAdmin,
        granted: Boolean(await contract.hasRole(role, legacyAdmin)),
      }))),
      transactions,
    });
  }

  console.log(JSON.stringify({
    schema: 'hazama-governance-migration-report/v1',
    mode,
    manifestHash,
    signer: signerAddress,
    timelock: timelockAddress,
    pauseGuard: pauseGuardAddress,
    targets: report,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

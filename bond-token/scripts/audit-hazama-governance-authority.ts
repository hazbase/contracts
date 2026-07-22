import fs from 'node:fs';
import { ethers } from 'hardhat';

type RoleDisposition = 'revoke' | 'retain' | 'absent';

type LegacyRolePolicy = {
  role: string;
  disposition: RoleDisposition;
  expected: boolean;
};

type OperationalBinding = {
  role: string;
  account: string;
  expected: boolean;
  purpose?: string;
};

type AuthorityTarget = {
  name: string;
  address: string;
  timelockRoles: string[];
  pauseGuardRole?: string;
  legacyRoles: LegacyRolePolicy[];
  operationalBindings?: OperationalBinding[];
};

type AuthorityInventory = {
  schema: 'hazama-governance-authority/v1';
  chainId: string;
  stage: string;
  legacyAdmin: string;
  targets: AuthorityTarget[];
};

function roleId(targetAddress: string, value: string): Promise<string> | string {
  if (value === 'DEFAULT_ADMIN_ROLE') return ethers.ZeroHash;
  if (ethers.isHexString(value, 32)) return value;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`Invalid role getter: ${value}`);
  }
  const reader = new ethers.Contract(
    targetAddress,
    [`function ${value}() view returns (bytes32)`],
    ethers.provider,
  );
  return reader[value]().then(String);
}

function loadInventory(): AuthorityInventory {
  const path = process.env.HAZAMA_GOVERNANCE_AUTHORITY_FILE?.trim();
  if (!path) throw new Error('HAZAMA_GOVERNANCE_AUTHORITY_FILE is required');
  const parsed = JSON.parse(fs.readFileSync(path, 'utf8')) as AuthorityInventory;
  if (parsed.schema !== 'hazama-governance-authority/v1') {
    throw new Error('Unsupported governance authority schema');
  }
  if (!/^\d+$/.test(parsed.chainId)) throw new Error('inventory.chainId must be an integer string');
  if (!parsed.stage?.trim()) throw new Error('inventory.stage is required');
  if (!ethers.isAddress(parsed.legacyAdmin)) throw new Error('inventory.legacyAdmin must be an EVM address');
  if (!Array.isArray(parsed.targets) || parsed.targets.length === 0) {
    throw new Error('inventory.targets must not be empty');
  }

  const targetAddresses = new Set<string>();
  for (const target of parsed.targets) {
    if (!target.name?.trim()) throw new Error('Each authority target requires a name');
    if (!ethers.isAddress(target.address)) throw new Error(`Invalid target address for ${target.name}`);
    const normalizedAddress = ethers.getAddress(target.address);
    if (targetAddresses.has(normalizedAddress)) throw new Error(`Duplicate target: ${normalizedAddress}`);
    targetAddresses.add(normalizedAddress);
    if (!Array.isArray(target.timelockRoles) || target.timelockRoles.length === 0) {
      throw new Error(`Target ${target.name} requires Timelock roles`);
    }
    if (!target.legacyRoles.some(({ role }) => role === 'DEFAULT_ADMIN_ROLE')) {
      throw new Error(`Target ${target.name} must inventory DEFAULT_ADMIN_ROLE`);
    }
    for (const binding of target.operationalBindings ?? []) {
      if (!ethers.isAddress(binding.account)) {
        throw new Error(`Invalid operational binding account for ${target.name}`);
      }
    }
  }
  return parsed;
}

async function hasRole(targetAddress: string, role: string, account: string): Promise<boolean> {
  const contract = new ethers.Contract(
    targetAddress,
    ['function hasRole(bytes32 role,address account) view returns (bool)'],
    ethers.provider,
  );
  return Boolean(await contract.hasRole(await roleId(targetAddress, role), account));
}

async function main() {
  const inventory = loadInventory();
  const network = await ethers.provider.getNetwork();
  if (network.chainId.toString() !== inventory.chainId) {
    throw new Error(`Chain mismatch: expected ${inventory.chainId}, received ${network.chainId}`);
  }

  const legacyAdmin = ethers.getAddress(inventory.legacyAdmin);
  const drift: Array<Record<string, unknown>> = [];
  const targets = [];

  for (const target of inventory.targets) {
    const targetAddress = ethers.getAddress(target.address);
    if (await ethers.provider.getCode(targetAddress) === '0x') {
      throw new Error(`Governance target is not deployed: ${target.name} (${targetAddress})`);
    }

    const legacyRoles = [];
    for (const policy of target.legacyRoles) {
      const granted = await hasRole(targetAddress, policy.role, legacyAdmin);
      legacyRoles.push({ ...policy, granted });
      if (granted !== policy.expected) {
        drift.push({
          target: target.name,
          role: policy.role,
          account: legacyAdmin,
          expected: policy.expected,
          actual: granted,
        });
      }
    }

    const operationalBindings = [];
    for (const binding of target.operationalBindings ?? []) {
      const account = ethers.getAddress(binding.account);
      const granted = await hasRole(targetAddress, binding.role, account);
      operationalBindings.push({ ...binding, account, granted });
      if (granted !== binding.expected) {
        drift.push({
          target: target.name,
          role: binding.role,
          account,
          purpose: binding.purpose ?? null,
          expected: binding.expected,
          actual: granted,
        });
      }
    }

    targets.push({
      name: target.name,
      address: targetAddress,
      legacyRoles,
      operationalBindings,
      migrationTarget: {
        name: target.name,
        address: targetAddress,
        timelockRoles: [...new Set(target.timelockRoles)],
        pauseGuardRole: target.pauseGuardRole ?? null,
        legacyAdmin,
        revokeLegacyRoles: legacyRoles
          .filter(({ disposition, granted }) => disposition === 'revoke' && granted)
          .map(({ role }) => role),
      },
    });
  }

  console.log(JSON.stringify({
    schema: 'hazama-governance-authority-report/v1',
    chainId: network.chainId.toString(),
    stage: inventory.stage,
    legacyAdmin,
    driftCount: drift.length,
    drift,
    targets,
  }, null, 2));

  if (drift.length > 0) process.exitCode = 2;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

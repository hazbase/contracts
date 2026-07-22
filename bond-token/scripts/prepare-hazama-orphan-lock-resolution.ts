import fs from 'node:fs';
import { ethers } from 'hardhat';
import { AbiCoder, Interface, ZeroHash } from 'ethers';

export type OrphanResolutionBatchInput = {
  lockManager: string;
  timelock: string;
  orderKey: string;
  incidentId: string;
  evidenceHash: string;
  minDelay: bigint;
};

export type OrphanResolutionBatch = {
  targets: string[];
  values: bigint[];
  payloads: string[];
  predecessor: string;
  salt: string;
  reasonCode: string;
  operationId: string;
  scheduleCalldata: string;
  executeCalldata: string;
};

type ResolutionManifest = {
  schema: 'hazama-orphan-lock-resolution/v1';
  incidentId: string;
  evidenceHash: string;
  lockManager: string;
  timelock: string;
  orderKey: string;
  expectedLock: {
    tokenStandard: number;
    token: string;
    backingOwner: string;
    classId: string;
    nonceId: string;
    amount: string;
    liquidAssetId: string;
    termsHash: string;
    expiresAt: string;
    liquidDeliveryTxid: string;
  };
};

const managerInterface = new Interface([
  'function RELEASER_ROLE() view returns (bytes32)',
  'function hasRole(bytes32 role,address account) view returns (bool)',
  'function grantRole(bytes32 role,address account)',
  'function revokeRole(bytes32 role,address account)',
  'function release(bytes32 orderId,bytes32 reasonCode)',
]);

const timelockInterface = new Interface([
  'function scheduleBatch(address[] targets,uint256[] values,bytes[] payloads,bytes32 predecessor,bytes32 salt,uint256 delay)',
  'function executeBatch(address[] targets,uint256[] values,bytes[] payloads,bytes32 predecessor,bytes32 salt) payable',
]);

export function buildOrphanResolutionBatch(input: OrphanResolutionBatchInput): OrphanResolutionBatch {
  const lockManager = ethers.getAddress(input.lockManager);
  const timelock = ethers.getAddress(input.timelock);
  const orderKey = bytes32(input.orderKey, 'orderKey');
  const evidenceHash = bytes32(input.evidenceHash, 'evidenceHash');
  const incidentId = normalizeIncidentId(input.incidentId);
  if (input.minDelay <= 0n) throw new Error('Timelock minimum delay must be greater than zero');

  const releaserRole = ethers.id('RELEASER_ROLE');
  const incidentHash = ethers.keccak256(ethers.toUtf8Bytes(incidentId));
  const coder = AbiCoder.defaultAbiCoder();
  const reasonCode = ethers.keccak256(coder.encode(
    ['string', 'bytes32', 'bytes32'],
    ['hazama_orphan_lock_resolution/v1', incidentHash, evidenceHash],
  ));
  const salt = ethers.keccak256(coder.encode(
    ['string', 'bytes32', 'bytes32', 'address', 'bytes32'],
    ['hazama_orphan_lock_resolution/v1', incidentHash, evidenceHash, lockManager, orderKey],
  ));
  const targets = [lockManager, lockManager, lockManager];
  const values = [0n, 0n, 0n];
  const payloads = [
    managerInterface.encodeFunctionData('grantRole', [releaserRole, timelock]),
    managerInterface.encodeFunctionData('release', [orderKey, reasonCode]),
    managerInterface.encodeFunctionData('revokeRole', [releaserRole, timelock]),
  ];
  const predecessor = ZeroHash;
  const operationId = ethers.keccak256(coder.encode(
    ['address[]', 'uint256[]', 'bytes[]', 'bytes32', 'bytes32'],
    [targets, values, payloads, predecessor, salt],
  ));
  return {
    targets,
    values,
    payloads,
    predecessor,
    salt,
    reasonCode,
    operationId,
    scheduleCalldata: timelockInterface.encodeFunctionData('scheduleBatch', [
      targets,
      values,
      payloads,
      predecessor,
      salt,
      input.minDelay,
    ]),
    executeCalldata: timelockInterface.encodeFunctionData('executeBatch', [
      targets,
      values,
      payloads,
      predecessor,
      salt,
    ]),
  };
}

function loadManifest(): ResolutionManifest {
  const path = process.env.HAZAMA_ORPHAN_RESOLUTION_MANIFEST_FILE?.trim();
  if (!path) throw new Error('HAZAMA_ORPHAN_RESOLUTION_MANIFEST_FILE is required');
  const manifest = JSON.parse(fs.readFileSync(path, 'utf8')) as ResolutionManifest;
  if (manifest.schema !== 'hazama-orphan-lock-resolution/v1') throw new Error('Unsupported resolution manifest schema');
  normalizeIncidentId(manifest.incidentId);
  bytes32(manifest.evidenceHash, 'evidenceHash');
  bytes32(manifest.orderKey, 'orderKey');
  if (!ethers.isAddress(manifest.lockManager)) throw new Error('manifest.lockManager must be an EVM address');
  if (!ethers.isAddress(manifest.timelock)) throw new Error('manifest.timelock must be an EVM address');
  if (!manifest.expectedLock || !Number.isInteger(manifest.expectedLock.tokenStandard)) {
    throw new Error('manifest.expectedLock.tokenStandard must be an integer');
  }
  if (manifest.expectedLock.tokenStandard < 0 || manifest.expectedLock.tokenStandard > 3) {
    throw new Error('manifest.expectedLock.tokenStandard must be 0 through 3');
  }
  if (!ethers.isAddress(manifest.expectedLock.token)) throw new Error('manifest.expectedLock.token must be an EVM address');
  if (!ethers.isAddress(manifest.expectedLock.backingOwner)) throw new Error('manifest.expectedLock.backingOwner must be an EVM address');
  positiveInteger(manifest.expectedLock.amount, 'expectedLock.amount');
  nonNegativeInteger(manifest.expectedLock.classId, 'expectedLock.classId');
  nonNegativeInteger(manifest.expectedLock.nonceId, 'expectedLock.nonceId');
  bytes32(manifest.expectedLock.liquidAssetId, 'expectedLock.liquidAssetId');
  bytes32(manifest.expectedLock.termsHash, 'expectedLock.termsHash');
  positiveInteger(manifest.expectedLock.expiresAt, 'expectedLock.expiresAt');
  bytes32(manifest.expectedLock.liquidDeliveryTxid, 'expectedLock.liquidDeliveryTxid');
  return manifest;
}

async function main() {
  const manifest = loadManifest();
  const lockManager = ethers.getAddress(manifest.lockManager);
  const timelockAddress = ethers.getAddress(manifest.timelock);
  if (await ethers.provider.getCode(lockManager) === '0x') throw new Error('Lock manager is not deployed');
  if (await ethers.provider.getCode(timelockAddress) === '0x') throw new Error('Timelock is not deployed');

  const manager = await ethers.getContractAt('GenericRwaBackingLockManager', lockManager);
  const timelock = await ethers.getContractAt('HazamaGovernanceTimelock', timelockAddress);
  const releaserRole = await manager.RELEASER_ROLE();
  if (String(releaserRole).toLowerCase() !== ethers.id('RELEASER_ROLE').toLowerCase()) {
    throw new Error('Lock manager RELEASER_ROLE is not canonical');
  }
  if (!(await manager.hasRole(ZeroHash, timelockAddress))) {
    throw new Error('Timelock does not hold DEFAULT_ADMIN_ROLE on the lock manager');
  }
  if (await manager.hasRole(releaserRole, timelockAddress)) {
    throw new Error('Timelock already holds RELEASER_ROLE; refuse to prepare a temporary-role batch');
  }
  if (await manager.paused()) throw new Error('Lock manager is paused');

  const orderKey = bytes32(manifest.orderKey, 'orderKey');
  const lock = await manager.getLock(orderKey);
  assertEqual(BigInt(lock.status), 1n, 'lock status');
  assertEqual(BigInt(lock.tokenStandard), BigInt(manifest.expectedLock.tokenStandard), 'token standard');
  assertAddress(lock.token, manifest.expectedLock.token, 'token');
  assertAddress(lock.backingOwner, manifest.expectedLock.backingOwner, 'backing owner');
  assertEqual(BigInt(lock.classId), BigInt(manifest.expectedLock.classId), 'class id');
  assertEqual(BigInt(lock.nonceId), BigInt(manifest.expectedLock.nonceId), 'nonce id');
  assertEqual(BigInt(lock.amount), BigInt(manifest.expectedLock.amount), 'amount');
  assertHex(lock.liquidAssetId, manifest.expectedLock.liquidAssetId, 'Liquid asset id');
  assertHex(lock.termsHash, manifest.expectedLock.termsHash, 'terms hash');
  assertEqual(BigInt(lock.expiresAt), BigInt(manifest.expectedLock.expiresAt), 'expiry');
  assertHex(lock.liquidDeliveryTxid, manifest.expectedLock.liquidDeliveryTxid, 'Liquid delivery txid');
  const latestBlock = await ethers.provider.getBlock('latest');
  if (!latestBlock) throw new Error('Latest EVM block is unavailable');
  if (BigInt(latestBlock.timestamp) <= BigInt(lock.expiresAt)) {
    throw new Error(`Orphan lock has not expired at block timestamp ${latestBlock.timestamp}`);
  }
  const totals = await manager.backingBalance(
    lock.tokenStandard,
    lock.token,
    lock.classId,
    lock.nonceId,
  );
  if (BigInt(totals.locked) < BigInt(lock.amount)) {
    throw new Error(`Backing totals are below the orphan lock amount: ${totals.locked} < ${lock.amount}`);
  }

  const minDelay = BigInt(await timelock.getMinDelay());
  const batch = buildOrphanResolutionBatch({
    lockManager,
    timelock: timelockAddress,
    orderKey,
    incidentId: manifest.incidentId,
    evidenceHash: manifest.evidenceHash,
    minDelay,
  });
  const onchainOperationId = await timelock.hashOperationBatch(
    batch.targets,
    batch.values,
    batch.payloads,
    batch.predecessor,
    batch.salt,
  );
  assertHex(onchainOperationId, batch.operationId, 'Timelock operation id');
  if (await timelock.isOperation(batch.operationId)) {
    throw new Error('The generated Timelock operation already exists');
  }

  const network = await ethers.provider.getNetwork();
  console.log(JSON.stringify({
    schema: 'hazama-orphan-lock-resolution-plan/v1',
    network: network.name,
    chainId: network.chainId.toString(),
    incidentId: manifest.incidentId,
    evidenceHash: bytes32(manifest.evidenceHash, 'evidenceHash'),
    lockManager,
    timelock: timelockAddress,
    orderKey,
    minimumDelaySeconds: minDelay.toString(),
    reasonCode: batch.reasonCode,
    operationId: batch.operationId,
    scheduleTransaction: {
      to: timelockAddress,
      value: '0',
      data: batch.scheduleCalldata,
    },
    executeTransaction: {
      to: timelockAddress,
      value: '0',
      data: batch.executeCalldata,
    },
    postConditions: [
      'The target lock status is Released.',
      'The Timelock does not hold RELEASER_ROLE.',
      'The incident evidence and execution transaction are recorded.',
      'A full DB, Sepolia, and Liquid reconciliation has no critical finding for this order.',
    ],
  }, null, 2));
}

function normalizeIncidentId(value: string): string {
  const normalized = String(value ?? '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(normalized)) {
    throw new Error('incidentId must be 8-128 URL-safe characters');
  }
  return normalized;
}

function bytes32(value: string, label: string): string {
  if (!ethers.isHexString(value, 32)) throw new Error(`${label} must be bytes32 hex`);
  return value.toLowerCase();
}

function positiveInteger(value: string, label: string): bigint {
  if (!/^\d+$/.test(String(value ?? '')) || BigInt(value) <= 0n) throw new Error(`${label} must be a positive integer`);
  return BigInt(value);
}

function nonNegativeInteger(value: string, label: string): bigint {
  if (!/^\d+$/.test(String(value ?? ''))) throw new Error(`${label} must be a non-negative integer`);
  return BigInt(value);
}

function assertEqual(actual: bigint, expected: bigint, label: string) {
  if (actual !== expected) throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
}

function assertAddress(actual: string, expected: string, label: string) {
  if (ethers.getAddress(actual) !== ethers.getAddress(expected)) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

function assertHex(actual: string, expected: string, label: string) {
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new Error(`${label} mismatch: expected ${expected}, got ${actual}`);
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}

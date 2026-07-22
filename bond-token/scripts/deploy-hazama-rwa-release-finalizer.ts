import { ethers } from 'hardhat';

function csv(name: string): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(',').map((part) => part.trim()).filter(Boolean) : [];
}

function feeOverrides() {
  const maxFee = process.env.EVM_MAX_FEE_GWEI;
  const maxPriorityFee = process.env.EVM_MAX_PRIORITY_FEE_GWEI;
  if (!maxFee && !maxPriorityFee) return {};
  if (!maxFee || !maxPriorityFee) {
    throw new Error('EVM_MAX_FEE_GWEI and EVM_MAX_PRIORITY_FEE_GWEI must be configured together');
  }
  return {
    maxFeePerGas: ethers.parseUnits(maxFee, 'gwei'),
    maxPriorityFeePerGas: ethers.parseUnits(maxPriorityFee, 'gwei'),
  };
}

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');

  const admin = process.env.HAZAMA_RELEASE_FINALIZER_ADMIN || deployer.address;
  const backingManager = process.env.EVM_LOCK_MANAGER_ADDRESS;
  const releaseDelayRaw = process.env.HAZAMA_RELEASE_DELAY_SECONDS;
  if (!ethers.isAddress(admin)) throw new Error('HAZAMA_RELEASE_FINALIZER_ADMIN must be an EVM address');
  if (!backingManager || !ethers.isAddress(backingManager)) {
    throw new Error('EVM_LOCK_MANAGER_ADDRESS must be an EVM address');
  }
  if (!releaseDelayRaw || !/^\d+$/.test(releaseDelayRaw)) {
    throw new Error('HAZAMA_RELEASE_DELAY_SECONDS must be an explicit positive integer');
  }
  const releaseDelaySeconds = BigInt(releaseDelayRaw);
  if (releaseDelaySeconds <= 0n || releaseDelaySeconds > 2n ** 64n - 1n) {
    throw new Error('HAZAMA_RELEASE_DELAY_SECONDS must fit uint64 and be greater than zero');
  }

  const approvers = csv('HAZAMA_APPROVER_ADDRESSES');
  const threshold = BigInt(process.env.HAZAMA_ATTESTATION_THRESHOLD || '0');
  const revokeReleasers = csv('HAZAMA_RELEASE_REVOKE_RELEASERS');
  const fees = feeOverrides();
  if (approvers.length === 0) throw new Error('HAZAMA_APPROVER_ADDRESSES must contain at least one approver');
  for (const address of [...approvers, ...revokeReleasers]) {
    if (!ethers.isAddress(address)) throw new Error(`Invalid EVM address: ${address}`);
  }
  if (threshold <= 0n || threshold > BigInt(approvers.length)) {
    throw new Error('HAZAMA_ATTESTATION_THRESHOLD must be between 1 and the approver count');
  }

  const finalizer = await ethers.deployContract('HazamaRwaReleaseFinalizer', [
    admin,
    backingManager,
    releaseDelaySeconds,
  ], fees);
  await finalizer.waitForDeployment();
  const finalizerAddress = await finalizer.getAddress();

  for (const approver of approvers) {
    await (await finalizer.setHazamaApprover(approver, true, { gasLimit: 150_000, ...fees })).wait();
  }
  await (await finalizer.setHazamaThreshold(threshold, { gasLimit: 150_000, ...fees })).wait();

  const manager = await ethers.getContractAt('GenericRwaBackingLockManager', backingManager);
  const releaserRole = await manager.RELEASER_ROLE();
  await (await manager.grantRole(releaserRole, finalizerAddress, { gasLimit: 150_000, ...fees })).wait();

  const revokedReleasers: string[] = [];
  for (const releaser of revokeReleasers) {
    if (releaser.toLowerCase() === finalizerAddress.toLowerCase()) {
      throw new Error('HAZAMA_RELEASE_REVOKE_RELEASERS must not include the new finalizer');
    }
    if (await manager.hasRole(releaserRole, releaser)) {
      await (await manager.revokeRole(releaserRole, releaser, { gasLimit: 150_000, ...fees })).wait();
      revokedReleasers.push(releaser);
    }
  }

  const network = await ethers.provider.getNetwork();
  const tx = finalizer.deploymentTransaction();
  console.log(JSON.stringify({
    contract: 'HazamaRwaReleaseFinalizer',
    network: network.name,
    chainId: Number(network.chainId),
    address: finalizerAddress,
    admin,
    deployer: deployer.address,
    backingManager,
    releaseDelaySeconds: releaseDelaySeconds.toString(),
    deploymentTx: tx?.hash ?? null,
    hazama: { approvers, threshold: threshold.toString() },
    revokedReleasers,
    next: [
      'Run contract and live release-path tests before revoking any remaining direct RELEASER_ROLE holder.',
      'Enable independent no-delivery candidate generation and quorum signing for the canonical Liquid cutoff.',
      'Only then set HAZAMA_RELEASE_REVOKE_RELEASERS and rerun the migration with explicit legacy releaser addresses.',
    ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

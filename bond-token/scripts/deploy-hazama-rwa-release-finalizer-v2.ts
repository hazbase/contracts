import { ethers } from 'hardhat';

function csv(name: string): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(',').map((part) => part.trim()).filter(Boolean) : [];
}

function enabled(name: string): boolean {
  return /^(1|true|yes)$/i.test(process.env[name]?.trim() ?? '');
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
  if (admin.toLowerCase() !== deployer.address.toLowerCase()) {
    throw new Error('HAZAMA_RELEASE_FINALIZER_ADMIN must equal the deployer during bootstrap configuration');
  }
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
  const activate = enabled('HAZAMA_RELEASE_FINALIZER_V2_ACTIVATE');
  const existingFinalizerAddress = process.env.HAZAMA_RELEASE_FINALIZER_V2_ADDRESS?.trim() || null;
  const revokeReleasers = csv('HAZAMA_RELEASE_REVOKE_RELEASERS');
  const fees = feeOverrides();
  if (approvers.length === 0) throw new Error('HAZAMA_APPROVER_ADDRESSES must contain at least one approver');
  for (const address of [...approvers, ...revokeReleasers]) {
    if (!ethers.isAddress(address)) throw new Error(`Invalid EVM address: ${address}`);
  }
  if (threshold <= 0n || threshold > BigInt(approvers.length)) {
    throw new Error('HAZAMA_ATTESTATION_THRESHOLD must be between 1 and the approver count');
  }
  if (!activate && revokeReleasers.length > 0) {
    throw new Error('HAZAMA_RELEASE_REVOKE_RELEASERS requires HAZAMA_RELEASE_FINALIZER_V2_ACTIVATE=true');
  }
  if (existingFinalizerAddress && !ethers.isAddress(existingFinalizerAddress)) {
    throw new Error('HAZAMA_RELEASE_FINALIZER_V2_ADDRESS must be an EVM address');
  }
  if (activate && !existingFinalizerAddress) {
    throw new Error('Activation requires the previously tested HAZAMA_RELEASE_FINALIZER_V2_ADDRESS');
  }

  const finalizer = existingFinalizerAddress
    ? await ethers.getContractAt('HazamaRwaReleaseFinalizerV2', existingFinalizerAddress)
    : await ethers.deployContract('HazamaRwaReleaseFinalizerV2', [
        admin,
        backingManager,
        releaseDelaySeconds,
      ], fees);
  if (!existingFinalizerAddress) await finalizer.waitForDeployment();
  const finalizerAddress = await finalizer.getAddress();
  if ((await finalizer.backingManager()).toLowerCase() !== backingManager.toLowerCase()) {
    throw new Error('Existing v2 finalizer backingManager does not match EVM_LOCK_MANAGER_ADDRESS');
  }
  if (await finalizer.releaseDelaySeconds() !== releaseDelaySeconds) {
    throw new Error('Existing v2 finalizer release delay does not match HAZAMA_RELEASE_DELAY_SECONDS');
  }
  const expectedTemplateHash = ethers.id('liquid-reservation-invalidation-release-v2');
  if ((await finalizer.RELEASE_TEMPLATE_HASH()).toLowerCase() !== expectedTemplateHash.toLowerCase()) {
    throw new Error('Existing finalizer does not implement the HAZAMA release v2 template');
  }
  const expectedReasonCode = ethers.id('liquid_reservation_invalidated');
  if ((await finalizer.RELEASE_REASON_CODE()).toLowerCase() !== expectedReasonCode.toLowerCase()) {
    throw new Error('Existing finalizer does not enforce the HAZAMA reservation invalidation reason');
  }

  for (const approver of approvers) {
    if (!(await finalizer.hazamaApprover(approver))) {
      await (await finalizer.setHazamaApprover(approver, true, { gasLimit: 150_000, ...fees })).wait();
    }
  }
  if (await finalizer.hazamaThreshold() !== threshold) {
    await (await finalizer.setHazamaThreshold(threshold, { gasLimit: 150_000, ...fees })).wait();
  }

  const manager = await ethers.getContractAt('GenericRwaBackingLockManager', backingManager);
  const releaserRole = await manager.RELEASER_ROLE();
  const revokedReleasers: string[] = [];
  if (activate) {
    if (await finalizer.paused()) {
      await (await finalizer.unpause({ gasLimit: 100_000, ...fees })).wait();
    }
    if (!(await manager.hasRole(releaserRole, finalizerAddress))) {
      await (await manager.grantRole(releaserRole, finalizerAddress, { gasLimit: 150_000, ...fees })).wait();
    }
    for (const releaser of revokeReleasers) {
      if (releaser.toLowerCase() === finalizerAddress.toLowerCase()) {
        throw new Error('HAZAMA_RELEASE_REVOKE_RELEASERS must not include the new finalizer');
      }
      if (await manager.hasRole(releaserRole, releaser)) {
        await (await manager.revokeRole(releaserRole, releaser, { gasLimit: 150_000, ...fees })).wait();
        revokedReleasers.push(releaser);
      }
    }
  } else {
    if (!(await finalizer.paused())) {
      await (await finalizer.pause({ gasLimit: 100_000, ...fees })).wait();
    }
  }

  const network = await ethers.provider.getNetwork();
  const tx = finalizer.deploymentTransaction();
  const paused = await finalizer.paused();
  const releaserRoleGranted = await manager.hasRole(releaserRole, finalizerAddress);
  console.log(JSON.stringify({
    contract: 'HazamaRwaReleaseFinalizerV2',
    schema: 'hazama_release_attestation_v2',
    templateId: 'liquid-reservation-invalidation-release-v2',
    network: network.name,
    chainId: Number(network.chainId),
    address: finalizerAddress,
    admin,
    deployer: deployer.address,
    backingManager,
    releaseDelaySeconds: releaseDelaySeconds.toString(),
    releaseReasonCode: expectedReasonCode,
    deploymentTx: tx?.hash ?? null,
    hazama: { approvers, threshold: threshold.toString() },
    activation: {
      active: activate,
      paused,
      releaserRoleGranted,
      revokedReleasers,
    },
    next: activate
      ? ['Run a timeout release v2 live test and verify the exact Liquid invalidation transaction evidence.']
      : [
          'Deploy and test the v2 backend and approver images with HAZAMA_RELEASE_REQUIRES_QUORUM=false.',
          'Run a terms-bound reservation invalidation test on Liquid testnet.',
          'Only then unpause, grant RELEASER_ROLE, and enable release quorum in Cloud Run.',
        ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

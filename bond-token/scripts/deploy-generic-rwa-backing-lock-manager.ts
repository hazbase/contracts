import { ethers } from 'hardhat';

function csv(name: string): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(',').map((part) => part.trim()).filter(Boolean) : [];
}

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');

  const admin = process.env.GENERIC_RWA_BACKING_LOCK_MANAGER_ADMIN || deployer.address;
  if (!ethers.isAddress(admin)) throw new Error('GENERIC_RWA_BACKING_LOCK_MANAGER_ADMIN must be an EVM address');

  const approvers = (
    csv('GENERIC_RWA_BACKING_LOCK_MANAGER_APPROVERS').length > 0
      ? csv('GENERIC_RWA_BACKING_LOCK_MANAGER_APPROVERS')
      : csv('HAZAMA_APPROVER_ADDRESSES')
  );
  const threshold = BigInt(process.env.GENERIC_RWA_BACKING_LOCK_MANAGER_THRESHOLD || process.env.HAZAMA_ATTESTATION_THRESHOLD || '0');
  for (const approver of approvers) {
    if (!ethers.isAddress(approver)) throw new Error(`Invalid approver address: ${approver}`);
  }

  const manager = await ethers.deployContract('GenericRwaBackingLockManager', [admin]);
  await manager.waitForDeployment();

  for (const approver of approvers) {
    await (await manager.setHazamaApprover(approver, true, { gasLimit: 150_000 })).wait();
  }
  if (threshold > 0n) {
    await (await manager.setHazamaThreshold(threshold, { gasLimit: 150_000 })).wait();
  }

  const network = await ethers.provider.getNetwork();
  const tx = manager.deploymentTransaction();

  console.log(JSON.stringify({
    contract: 'GenericRwaBackingLockManager',
    network: network.name,
    chainId: Number(network.chainId),
    address: await manager.getAddress(),
    admin,
    deployer: deployer.address,
    deploymentTx: tx?.hash ?? null,
    hazama: {
      approvers,
      threshold: threshold.toString(),
    },
    next: [
      'Approve this manager as BondToken operator for the configured backing owner.',
      'Set EVM_LOCK_MANAGER_ADDRESS to this address.',
      'Set HAZAMA_CONSUME_ONCHAIN_ATTESTATIONS=true after the service points to this manager.',
    ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

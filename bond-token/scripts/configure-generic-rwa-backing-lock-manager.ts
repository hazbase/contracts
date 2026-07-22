import { ethers } from 'hardhat';

function csv(name: string): string[] {
  const raw = process.env[name]?.trim();
  return raw ? raw.split(',').map((part) => part.trim()).filter(Boolean) : [];
}

async function main() {
  const [admin] = await ethers.getSigners();
  if (!admin) throw new Error('No admin signer configured');

  const managerAddress = process.env.GENERIC_RWA_BACKING_LOCK_MANAGER_ADDRESS || process.env.EVM_LOCK_MANAGER_ADDRESS;
  if (!managerAddress || !ethers.isAddress(managerAddress)) {
    throw new Error('GENERIC_RWA_BACKING_LOCK_MANAGER_ADDRESS or EVM_LOCK_MANAGER_ADDRESS must be an EVM address');
  }

  const approvers = (
    csv('GENERIC_RWA_BACKING_LOCK_MANAGER_APPROVERS').length > 0
      ? csv('GENERIC_RWA_BACKING_LOCK_MANAGER_APPROVERS')
      : csv('HAZAMA_APPROVER_ADDRESSES')
  );
  const threshold = BigInt(process.env.GENERIC_RWA_BACKING_LOCK_MANAGER_THRESHOLD || process.env.HAZAMA_ATTESTATION_THRESHOLD || '0');
  for (const approver of approvers) {
    if (!ethers.isAddress(approver)) throw new Error(`Invalid approver address: ${approver}`);
  }

  const manager = await ethers.getContractAt(
    [
      'function setHazamaApprover(address approver,bool enabled)',
      'function setHazamaThreshold(uint256 threshold)',
      'function hazamaApprover(address approver) view returns (bool)',
      'function hazamaApproverCount() view returns (uint256)',
      'function hazamaThreshold() view returns (uint256)',
    ],
    managerAddress,
    admin
  );

  const changedApprovers: string[] = [];
  for (const approver of approvers) {
    const alreadyEnabled = await manager.hazamaApprover(approver);
    if (!alreadyEnabled) {
      await (await manager.setHazamaApprover(approver, true, { gasLimit: 150_000 })).wait();
      changedApprovers.push(approver);
    }
  }

  let thresholdTxHash: string | null = null;
  if (threshold > 0n) {
    const currentThreshold = await manager.hazamaThreshold();
    if (currentThreshold !== threshold) {
      const tx = await manager.setHazamaThreshold(threshold, { gasLimit: 150_000 });
      thresholdTxHash = tx.hash;
      await tx.wait();
    }
  }

  const network = await ethers.provider.getNetwork();

  console.log(JSON.stringify({
    contract: 'GenericRwaBackingLockManager',
    action: 'configureHazamaApprovers',
    network: network.name,
    chainId: Number(network.chainId),
    address: managerAddress,
    admin: admin.address,
    approvers,
    changedApprovers,
    approverCount: (await manager.hazamaApproverCount()).toString(),
    threshold: (await manager.hazamaThreshold()).toString(),
    thresholdTxHash,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

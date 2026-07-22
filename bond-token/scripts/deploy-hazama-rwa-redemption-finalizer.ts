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

  const admin = process.env.HAZAMA_REDEMPTION_FINALIZER_ADMIN || deployer.address;
  const redemptionManager = process.env.EVM_REDEMPTION_MANAGER_ADDRESS;
  if (!ethers.isAddress(admin)) throw new Error('HAZAMA_REDEMPTION_FINALIZER_ADMIN must be an EVM address');
  if (!redemptionManager || !ethers.isAddress(redemptionManager)) {
    throw new Error('EVM_REDEMPTION_MANAGER_ADDRESS must be an EVM address');
  }

  const approvers = csv('HAZAMA_APPROVER_ADDRESSES');
  const threshold = BigInt(process.env.HAZAMA_ATTESTATION_THRESHOLD || '0');
  const fees = feeOverrides();
  if (approvers.length === 0) throw new Error('HAZAMA_APPROVER_ADDRESSES must contain at least one approver');
  for (const approver of approvers) {
    if (!ethers.isAddress(approver)) throw new Error(`Invalid approver address: ${approver}`);
  }
  if (threshold <= 0n || threshold > BigInt(approvers.length)) {
    throw new Error('HAZAMA_ATTESTATION_THRESHOLD must be between 1 and the approver count');
  }

  const finalizer = await ethers.deployContract('HazamaRwaRedemptionFinalizer', [admin, redemptionManager], fees);
  await finalizer.waitForDeployment();
  const finalizerAddress = await finalizer.getAddress();

  for (const approver of approvers) {
    await (await finalizer.setHazamaApprover(approver, true, { gasLimit: 150_000, ...fees })).wait();
  }
  await (await finalizer.setHazamaThreshold(threshold, { gasLimit: 150_000, ...fees })).wait();

  const manager = await ethers.getContractAt('GenericRwaRedemptionManager', redemptionManager);
  const recorderRole = await manager.RECORDER_ROLE();
  await (await manager.grantRole(recorderRole, finalizerAddress, { gasLimit: 150_000, ...fees })).wait();

  const network = await ethers.provider.getNetwork();
  const tx = finalizer.deploymentTransaction();
  console.log(JSON.stringify({
    contract: 'HazamaRwaRedemptionFinalizer',
    network: network.name,
    chainId: Number(network.chainId),
    address: finalizerAddress,
    admin,
    deployer: deployer.address,
    redemptionManager,
    deploymentTx: tx?.hash ?? null,
    hazama: { approvers, threshold: threshold.toString() },
    next: [
      `Set HAZAMA_REDEMPTION_FINALIZER_ADDRESS=${finalizerAddress} on the settlement service.`,
      'Run a new redemption so ApproverNodes sign the finalizer contract as the EIP-712 verifying contract.',
      'After a successful live finalization, revoke RECORDER_ROLE from the legacy backend relay account.',
    ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

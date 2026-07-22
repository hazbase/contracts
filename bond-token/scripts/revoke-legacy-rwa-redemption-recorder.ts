import { ethers } from 'hardhat';

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
  if (process.env.CONFIRM_REVOKE_LEGACY_REDEMPTION_RECORDER !== '1') {
    throw new Error('Set CONFIRM_REVOKE_LEGACY_REDEMPTION_RECORDER=1 to revoke the legacy recorder role');
  }

  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');
  const redemptionManagerAddress = process.env.EVM_REDEMPTION_MANAGER_ADDRESS;
  const finalizerAddress = process.env.HAZAMA_REDEMPTION_FINALIZER_ADDRESS;
  const legacyRecorder = process.env.HAZAMA_LEGACY_REDEMPTION_RECORDER ?? deployer.address;
  if (!redemptionManagerAddress || !ethers.isAddress(redemptionManagerAddress)) {
    throw new Error('EVM_REDEMPTION_MANAGER_ADDRESS must be an EVM address');
  }
  if (!finalizerAddress || !ethers.isAddress(finalizerAddress)) {
    throw new Error('HAZAMA_REDEMPTION_FINALIZER_ADDRESS must be an EVM address');
  }
  if (!ethers.isAddress(legacyRecorder)) {
    throw new Error('HAZAMA_LEGACY_REDEMPTION_RECORDER must be an EVM address');
  }
  if (legacyRecorder.toLowerCase() === finalizerAddress.toLowerCase()) {
    throw new Error('Refusing to revoke RECORDER_ROLE from the HAZAMA finalizer');
  }

  const manager = await ethers.getContractAt('GenericRwaRedemptionManager', redemptionManagerAddress);
  const recorderRole = await manager.RECORDER_ROLE();
  if (!(await manager.hasRole(recorderRole, finalizerAddress))) {
    throw new Error('HAZAMA finalizer does not hold RECORDER_ROLE');
  }
  if (!(await manager.hasRole(recorderRole, legacyRecorder))) {
    console.log(JSON.stringify({
      redemptionManager: redemptionManagerAddress,
      finalizer: finalizerAddress,
      legacyRecorder,
      revoked: false,
      reason: 'legacy_recorder_does_not_hold_role',
    }, null, 2));
    return;
  }

  const tx = await manager.revokeRole(recorderRole, legacyRecorder, {
    gasLimit: 150_000,
    ...feeOverrides(),
  });
  await tx.wait();
  console.log(JSON.stringify({
    redemptionManager: redemptionManagerAddress,
    finalizer: finalizerAddress,
    legacyRecorder,
    recorderRole,
    txHash: tx.hash,
    revoked: !(await manager.hasRole(recorderRole, legacyRecorder)),
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

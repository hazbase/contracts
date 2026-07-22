import { ethers } from 'hardhat';

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');

  const admin = process.env.GENERIC_RWA_LOCK_MANAGER_ADMIN || deployer.address;
  if (!ethers.isAddress(admin)) throw new Error('GENERIC_RWA_LOCK_MANAGER_ADMIN must be an EVM address');

  const manager = await ethers.deployContract('GenericRwaBackingLockManager', [admin]);
  await manager.waitForDeployment();

  const address = await manager.getAddress();
  const tx = manager.deploymentTransaction();

  console.log(JSON.stringify({
    contract: 'GenericRwaBackingLockManager',
    network: (await ethers.provider.getNetwork()).name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    address,
    admin,
    deployer: deployer.address,
    deploymentTx: tx?.hash ?? null,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

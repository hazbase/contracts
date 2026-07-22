import { ethers } from 'hardhat';

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');

  const admin = process.env.GENERIC_RWA_REDEMPTION_MANAGER_ADMIN || deployer.address;
  if (!ethers.isAddress(admin)) throw new Error('GENERIC_RWA_REDEMPTION_MANAGER_ADMIN must be an EVM address');

  const manager = await ethers.deployContract('GenericRwaRedemptionManager', [admin]);
  await manager.waitForDeployment();

  const network = await ethers.provider.getNetwork();
  const tx = manager.deploymentTransaction();

  console.log(JSON.stringify({
    contract: 'GenericRwaRedemptionManager',
    network: network.name,
    chainId: Number(network.chainId),
    address: await manager.getAddress(),
    admin,
    deployer: deployer.address,
    deploymentTx: tx?.hash ?? null,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

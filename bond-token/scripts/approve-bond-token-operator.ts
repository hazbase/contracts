import { ethers } from 'hardhat';

async function main() {
  const [owner] = await ethers.getSigners();
  if (!owner) throw new Error('No owner signer configured');

  const tokenAddress = process.env.BOND_TOKEN_ADDRESS || process.env.ASSET_BINDING_EVM_TOKEN;
  const operatorAddress = process.env.OPERATOR_ADDRESS || process.env.EVM_LOCK_MANAGER_ADDRESS;
  const approved = (process.env.APPROVED || 'true').toLowerCase() !== 'false';

  if (!tokenAddress || !ethers.isAddress(tokenAddress)) {
    throw new Error('BOND_TOKEN_ADDRESS or ASSET_BINDING_EVM_TOKEN must be an EVM address');
  }
  if (!operatorAddress || !ethers.isAddress(operatorAddress)) {
    throw new Error('OPERATOR_ADDRESS or EVM_LOCK_MANAGER_ADDRESS must be an EVM address');
  }

  const bond = await ethers.getContractAt(
    [
      'function isApprovedForAll(address owner,address operator) view returns (bool)',
      'function setApprovalForAll(address operator,bool approved)',
    ],
    tokenAddress,
    owner
  );

  const before = await bond.isApprovedForAll(owner.address, operatorAddress);
  let txHash: string | null = null;
  if (before !== approved) {
    const tx = await bond.setApprovalForAll(operatorAddress, approved);
    txHash = tx.hash;
    await tx.wait();
  }
  const after = await bond.isApprovedForAll(owner.address, operatorAddress);
  const network = await ethers.provider.getNetwork();

  console.log(JSON.stringify({
    contract: 'BondToken',
    action: 'setApprovalForAll',
    network: network.name,
    chainId: Number(network.chainId),
    token: tokenAddress,
    owner: owner.address,
    operator: operatorAddress,
    requestedApproved: approved,
    before,
    after,
    txHash,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

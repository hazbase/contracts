import { Interface, MaxUint256 } from 'ethers';
import { ethers } from 'hardhat';

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer configured');

  const manager = process.env.GENERIC_RWA_LOCK_MANAGER_ADDRESS
    || process.env.EVM_LOCK_MANAGER_ADDRESS;
  if (!manager || !ethers.isAddress(manager)) {
    throw new Error('GENERIC_RWA_LOCK_MANAGER_ADDRESS or EVM_LOCK_MANAGER_ADDRESS must be set');
  }

  const erc20Amount = BigInt(process.env.GENERIC_RWA_SMOKE_ERC20_AMOUNT || '1000');
  const erc1155Id = BigInt(process.env.GENERIC_RWA_SMOKE_ERC1155_ID || '1');
  const erc1155Amount = BigInt(process.env.GENERIC_RWA_SMOKE_ERC1155_AMOUNT || '1000');

  const erc20 = await ethers.deployContract('MockERC20');
  await erc20.waitForDeployment();
  const erc20Address = await erc20.getAddress();
  console.log(`deployed MockERC20 ${erc20Address}`);
  const erc20Interface = new Interface([
    'function mint(address to,uint256 amount)',
    'function approve(address spender,uint256 amount) returns (bool)',
  ]);
  await (await deployer.sendTransaction({
    to: erc20Address,
    data: erc20Interface.encodeFunctionData('mint', [deployer.address, erc20Amount]),
    gasLimit: 200000n,
  })).wait(1);
  await (await deployer.sendTransaction({
    to: erc20Address,
    data: erc20Interface.encodeFunctionData('approve', [manager, MaxUint256]),
    gasLimit: 200000n,
  })).wait(1);
  console.log(`minted/approved MockERC20 ${erc20Address}`);

  const erc1155 = await ethers.deployContract('MockERC1155');
  await erc1155.waitForDeployment();
  const erc1155Address = await erc1155.getAddress();
  console.log(`deployed MockERC1155 ${erc1155Address}`);
  const erc1155Interface = new Interface([
    'function mint(address to,uint256 id,uint256 amount)',
    'function setApprovalForAll(address operator,bool approved)',
  ]);
  await (await deployer.sendTransaction({
    to: erc1155Address,
    data: erc1155Interface.encodeFunctionData('mint', [deployer.address, erc1155Id, erc1155Amount]),
    gasLimit: 300000n,
  })).wait(1);
  await (await deployer.sendTransaction({
    to: erc1155Address,
    data: erc1155Interface.encodeFunctionData('setApprovalForAll', [manager, true]),
    gasLimit: 200000n,
  })).wait(1);
  console.log(`minted/approved MockERC1155 ${erc1155Address}`);

  const erc721 = await ethers.deployContract('MockERC721');
  await erc721.waitForDeployment();
  const erc721Address = await erc721.getAddress();
  console.log(`deployed MockERC721 ${erc721Address}`);
  const erc721Interface = new Interface([
    'function mint(address to,uint256 tokenId)',
    'function approve(address to,uint256 tokenId)',
  ]);
  await (await deployer.sendTransaction({
    to: erc721Address,
    data: erc721Interface.encodeFunctionData('mint', [deployer.address, 1]),
    gasLimit: 200000n,
  })).wait(1);
  await (await deployer.sendTransaction({
    to: erc721Address,
    data: erc721Interface.encodeFunctionData('approve', [manager, 1]),
    gasLimit: 200000n,
  })).wait(1);
  console.log(`minted/approved MockERC721 ${erc721Address}`);

  console.log(JSON.stringify({
    network: (await ethers.provider.getNetwork()).name,
    chainId: Number((await ethers.provider.getNetwork()).chainId),
    owner: deployer.address,
    manager,
    erc20: {
      address: erc20Address,
      minted: erc20Amount.toString(),
      approved: true,
    },
    erc1155: {
      address: erc1155Address,
      id: erc1155Id.toString(),
      minted: erc1155Amount.toString(),
      approved: true,
    },
    erc721: {
      address: erc721Address,
      tokenId: '1',
      approved: true,
    },
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// EIP-712 Offer type (mirrors AgreementManager.OFFER_TYPEHASH field order).
const offerTypes = {
  Offer: [
    { name: 'issuer', type: 'address' },
    { name: 'investor', type: 'address' },
    { name: 'tokenAddress', type: 'address' },
    { name: 'partition', type: 'bytes32' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'amount', type: 'uint256' },
    { name: 'classId', type: 'uint256' },
    { name: 'nonceId', type: 'uint256' },
    { name: 'documentHash', type: 'bytes32' },
    { name: 'documentURI', type: 'string' },
    { name: 'expiry', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
  ],
};

async function deployAgreementManager(adminAddress: string) {
  const factory = await ethers.getContractFactory('AgreementManager');
  const manager = await upgrades.deployProxy(factory, [adminAddress, []], {
    kind: 'uups',
    initializer: 'initialize',
  });
  await manager.waitForDeployment();
  return manager;
}

function computeOfferId(o: any) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  return ethers.keccak256(
    coder.encode(
      ['bytes1', 'address', 'bytes1', 'address', 'bytes1', 'address',
       'bytes32', 'uint256', 'uint256', 'uint256', 'uint256', 'bytes32', 'bytes32', 'uint256', 'uint256'],
      ['0x01', o.issuer, '0x02', o.investor, '0x03', o.tokenAddress,
       o.partition, o.tokenId, o.amount, o.classId, o.nonceId,
       o.documentHash, ethers.keccak256(ethers.toUtf8Bytes(o.documentURI)), o.expiry, o.nonce],
    ),
  );
}

async function buildOffer(manager: any, issuer: string, investor: string, token: string, partition: string, amount: bigint) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const latest = await ethers.provider.getBlock('latest');
  const domain = { name: 'AgreementManager', version: '1', chainId, verifyingContract: await manager.getAddress() };
  const offer = {
    issuer, investor, tokenAddress: token, partition, tokenId: 0n, amount,
    classId: 0n, nonceId: 0n,
    documentHash: ethers.keccak256(ethers.toUtf8Bytes('erc1400-doc')),
    documentURI: 'ipfs://hazbase/erc1400',
    expiry: BigInt((latest!.timestamp) + 3600), nonce: 1n,
  };
  return { domain, offer };
}

async function submitOffer(manager: any, signer: any, offer: any, sig: string) {
  return manager.connect(signer).offer(
    offer.investor, offer.tokenAddress, offer.partition, offer.tokenId, offer.amount,
    offer.classId, offer.nonceId, offer.documentHash, offer.documentURI, offer.expiry, offer.nonce,
    sig, ethers.ZeroAddress,
  );
}

describe('AgreementManager ERC-1400 escrow', function () {
  const partition = ethers.encodeBytes32String('SERIES-A');
  const amount = 1_000n;

  it('escrows the issuer partition tokens on offer and settles them to the investor on accept', async function () {
    const [admin, issuer, investor] = await ethers.getSigners();
    const erc1400 = await ethers.deployContract('MockERC1400');
    const manager = await deployAgreementManager(admin.address);
    const managerAddr = await manager.getAddress();

    await erc1400.mint(partition, issuer.address, amount);
    await erc1400.connect(issuer).authorizeOperator(managerAddr);

    const { domain, offer } = await buildOffer(manager, issuer.address, investor.address, await erc1400.getAddress(), partition, amount);
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const investorSig = await investor.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer);

    // offer(): escrow pulls FROM the issuer INTO the manager.
    await submitOffer(manager, issuer, offer, issuerSig);
    expect(await erc1400.balanceOfByPartition(partition, issuer.address)).to.equal(0n);
    expect(await erc1400.balanceOfByPartition(partition, managerAddr)).to.equal(amount);

    // acceptOffer(): settlement delivers the escrowed tokens to the investor.
    await manager.connect(investor).acceptOffer(offerId, investorSig);
    expect(await erc1400.balanceOfByPartition(partition, investor.address)).to.equal(amount);
    expect(await erc1400.balanceOfByPartition(partition, managerAddr)).to.equal(0n);
  });

  it('reverts the offer when the manager is NOT an authorized operator (escrow genuinely pulls from issuer)', async function () {
    const [admin, issuer, investor] = await ethers.getSigners();
    const erc1400 = await ethers.deployContract('MockERC1400');
    const manager = await deployAgreementManager(admin.address);

    await erc1400.mint(partition, issuer.address, amount);
    // NOTE: no authorizeOperator -> the operator-scoped escrow transfer must revert,
    // proving escrow pulls from the issuer rather than no-op self-transferring.
    const { domain, offer } = await buildOffer(manager, issuer.address, investor.address, await erc1400.getAddress(), partition, amount);
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);

    await expect(submitOffer(manager, issuer, offer, issuerSig)).to.be.reverted;
  });

  it('cancels an escrowed offer back to the issuer', async function () {
    const [admin, issuer, investor] = await ethers.getSigners();
    const erc1400 = await ethers.deployContract('MockERC1400');
    const manager = await deployAgreementManager(admin.address);
    const managerAddr = await manager.getAddress();

    await erc1400.mint(partition, issuer.address, amount);
    await erc1400.connect(issuer).authorizeOperator(managerAddr);
    const { domain, offer } = await buildOffer(manager, issuer.address, investor.address, await erc1400.getAddress(), partition, amount);
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer);

    await submitOffer(manager, issuer, offer, issuerSig);
    expect(await erc1400.balanceOfByPartition(partition, managerAddr)).to.equal(amount);

    await manager.connect(issuer).cancelOffer(offerId);
    expect(await erc1400.balanceOfByPartition(partition, issuer.address)).to.equal(amount);
    expect(await erc1400.balanceOfByPartition(partition, managerAddr)).to.equal(0n);
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

async function deployMarketFixture() {
  const [admin, seller, buyer] = await ethers.getSigners();
  const assetToken = await ethers.deployContract('MockERC721', ['Incident Asset NFT', 'IANFT']);
  const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const whitelist = await ethers.deployContract('MockWhitelist');
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const marketFactory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 100, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();
  return { admin, seller, buyer, assetToken, paymentToken, whitelist, splitter, market };
}

describe('MarketManager incident-response coverage', function () {
  it('blocks primary asks and vouchers for buyers whose KYC was revoked, then respects market pause', async function () {
    const { seller, buyer, assetToken, whitelist, market } = await deployMarketFixture();

    await market.setWhitelist(whitelist.target);
    await whitelist.setWhitelisted(buyer.address, true);

    await assetToken.mint(seller.address);
    await assetToken.mint(seller.address);
    await assetToken.connect(seller).setApprovalForAll(market.target, true);

    await market.connect(seller).createAsk(
      { kind: 1, token: assetToken.target, id: 1n, nonceId: 0n, amount: 0n },
      100n,
      ethers.ZeroAddress,
      1n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash
    );

    await whitelist.setWhitelisted(buyer.address, false);
    await expect(
      market.connect(buyer).fillAsk(0, 1n, { value: 100n })
    ).to.be.revertedWith('KYCfail');

    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const domain = {
      name: 'MarketManager',
      version: '1',
      chainId,
      verifyingContract: await market.getAddress(),
    };
    const types = {
      Asset: [
        { name: 'kind', type: 'uint8' },
        { name: 'token', type: 'address' },
        { name: 'id', type: 'uint256' },
        { name: 'nonceId', type: 'uint256' },
        { name: 'amount', type: 'uint256' },
      ],
      Voucher: [
        { name: 'asset', type: 'Asset' },
        { name: 'price', type: 'uint256' },
        { name: 'paymentToken', type: 'address' },
        { name: 'quantity', type: 'uint256' },
        { name: 'maxPerWallet', type: 'uint64' },
        { name: 'startTime', type: 'uint64' },
        { name: 'endTime', type: 'uint64' },
        { name: 'royaltyReceiver', type: 'address' },
        { name: 'royaltyBps', type: 'uint16' },
        { name: 'salt', type: 'uint256' },
        { name: 'seller', type: 'address' },
      ],
    };
    const voucher = {
      asset: { kind: 1, token: await assetToken.getAddress(), id: 2n, nonceId: 0n, amount: 0n },
      price: 150n,
      paymentToken: ethers.ZeroAddress,
      quantity: 1n,
      maxPerWallet: 0,
      startTime: 0,
      endTime: 0,
      royaltyReceiver: ethers.ZeroAddress,
      royaltyBps: 0,
      salt: 1n,
      seller: seller.address,
    };
    const sig = await seller.signTypedData(domain, types, voucher);

    await expect(
      market.connect(buyer).fillVoucher(voucher, 1n, sig, { value: 150n })
    ).to.be.revertedWith('KYCfail');

    await whitelist.setWhitelisted(buyer.address, true);
    await market.pause();
    await expect(
      market.connect(buyer).fillAsk(0, 1n, { value: 100n })
    ).to.be.reverted;
  });

  it('blocks delegated secondary settlement for a buyer revoked after onboarding and respects pause', async function () {
    const [admin, seller, buyer] = await ethers.getSigners();
    const bondToken = await ethers.deployContract('MockBondToken');
    const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const whitelist = await ethers.deployContract('MockWhitelist');
    const splitter = await ethers.deployContract('MockSplitter', [false]);
    const agreement = await ethers.deployContract('MockAgreementManager');
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 100, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await market.setPaymentToken(paymentToken.target, true);
    await market.setWhitelist(whitelist.target);
    await whitelist.setWhitelisted(buyer.address, true);

    await bondToken.mint(seller.address, 1n, 1n, 200n);
    await bondToken.connect(seller).setApprovalForAll(agreement.target, true);
    await paymentToken.mint(buyer.address, 300_000n);
    await paymentToken.connect(buyer).approve(market.target, 300_000n);

    const offerId = ethers.id('INCIDENT-DELEGATED-SECONDARY-2026-03-19');
    await agreement.setOffer({
      issuer: seller.address,
      investor: buyer.address,
      tokenAddress: bondToken.target,
      partition: ethers.ZeroHash,
      tokenId: 0n,
      classId: 1n,
      nonceId: 1n,
      amount: 200n,
      documentHash: ethers.ZeroHash,
      documentURI: 'ipfs://incident-secondary-offer',
      expiry: 0n,
      nonce: 1n,
      delegatedTo: market.target,
      issuerSig: '0x',
      status: 1,
    });

    await market.connect(seller).createAsk(
      { kind: 3, token: bondToken.target, id: 1n, nonceId: 1n, amount: 1n },
      1_000n,
      paymentToken.target,
      200n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      agreement.target,
      offerId
    );

    await whitelist.setWhitelisted(buyer.address, false);
    await expect(
      market.connect(buyer).fillAskWithSig(0, 200n, '0x1234')
    ).to.be.revertedWith('KYCfail');

    await whitelist.setWhitelisted(buyer.address, true);
    await market.pause();
    await expect(
      market.connect(buyer).fillAskWithSig(0, 200n, '0x1234')
    ).to.be.reverted;
  });
});

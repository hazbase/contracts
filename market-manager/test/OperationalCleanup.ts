import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitOpsLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_OPS_LEDGER_OUTPUT === '1') {
    console.log(`RWA_OPS_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployPrimaryAskFixture() {
  const [admin, seller, buyer] = await ethers.getSigners();
  const assetToken = await ethers.deployContract('MockERC721', ['Ops Incident Asset', 'OIA']);
  const whitelist = await ethers.deployContract('MockWhitelist');
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const marketFactory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 100, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();

  await market.setWhitelist(whitelist.target);
  await whitelist.setWhitelisted(buyer.address, true);
  await assetToken.mint(seller.address);
  await assetToken.connect(seller).setApprovalForAll(market.target, true);

  return { admin, seller, buyer, assetToken, whitelist, market };
}

async function deployDelegatedBondFixture() {
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

  const offerId = ethers.id('OPS-DELEGATED-SECONDARY-2026-03-19');
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
    documentURI: 'ipfs://ops/delegated-secondary-offer',
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
    offerId,
  );

  return { seller, buyer, bondToken, market };
}

async function deployBondAskFixture() {
  const [admin, seller, buyer] = await ethers.getSigners();
  const bondToken = await ethers.deployContract('MockBondToken');
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

  await market.setPaymentToken(paymentToken.target, true);
  await market.setWhitelist(whitelist.target);
  await whitelist.setWhitelisted(buyer.address, true);

  await bondToken.mint(seller.address, 1n, 1n, 200n);
  await bondToken.connect(seller).setApprovalForAll(market.target, true);
  await paymentToken.mint(buyer.address, 300_000n);
  await paymentToken.connect(buyer).approve(market.target, 300_000n);

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
    ethers.ZeroAddress,
    ethers.ZeroHash,
  );

  return { seller, buyer, bondToken, market };
}

describe('MarketManager operational cleanup coverage', function () {
  it('cancels a live non-delegated ask after incident while market pause blocks fills', async function () {
    const { seller, buyer, assetToken, market } = await deployPrimaryAskFixture();

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
      ethers.ZeroHash,
    );

    await market.pause();
    await expect(market.connect(buyer).fillAsk(0, 1n, { value: 100n })).to.be.reverted;
    await expect(market.connect(seller).cancelAsk(0)).to.emit(market, 'AskCancelled');

    expect(await assetToken.ownerOf(1n)).to.equal(seller.address);

    await market.unpause();
    await expect(market.connect(buyer).fillAsk(0, 1n, { value: 100n })).to.be.revertedWith('bad qty');
  });

  it('emits ops ledger for OPS-REC-01 delegated market freeze before OTC unwind', async function () {
    const { buyer, market } = await deployDelegatedBondFixture();

    await market.pause();
    await expect(market.connect(buyer).fillAskWithSig(0, 200n, '0x1234')).to.be.reverted;

    emitOpsLedger({
      scenario: 'OPS-REC-01',
      source: 'market-manager',
      ledger: {
        market_paused_state: 'paused',
      },
      checks: {
        delegated_market_frozen: true,
      },
    });
  });

  it('emits ops ledger for OPS-REC-02 secondary trading freeze while retirement proceeds', async function () {
    const { seller, buyer, bondToken, market } = await deployBondAskFixture();

    await market.pause();
    await expect(market.connect(buyer).fillAsk(0, 200n)).to.be.reverted;
    await expect(market.connect(seller).cancelAsk(0)).to.emit(market, 'AskCancelled');

    expect(await bondToken.balanceOf(seller.address, 1n, 1n)).to.equal(200n);

    emitOpsLedger({
      scenario: 'OPS-REC-02',
      source: 'market-manager',
      ledger: {
        market_paused_state: 'paused',
      },
      checks: {
        secondary_trading_frozen: true,
      },
    });
  });
});

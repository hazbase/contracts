import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRwaLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_LEDGER_OUTPUT === '1') {
    console.log(`RWA_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('MarketManager case-study coverage', function () {
  it('rejects a second fill once an ask is sold out', async function () {
    const [admin, seller, buyerOne, buyerTwo] = await ethers.getSigners();
    const assetToken = await ethers.deployContract('MockERC721', ['Asset NFT', 'ANFT']);
    const splitter = await ethers.deployContract('MockSplitter', [false]);
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 0, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await assetToken.mint(seller.address);
    await assetToken.connect(seller).approve(market.target, 1n);

    await market.connect(seller).createAsk(
      {
        kind: 1,
        token: assetToken.target,
        id: 1n,
        nonceId: 0n,
        amount: 0n,
      },
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

    await expect(market.connect(buyerOne).fillAsk(0, 1, { value: 100n }))
      .to.emit(market, 'AskFilled');

    const ask = await market.ask(0);
    expect(ask.quantity).to.equal(0n);
    expect(await assetToken.ownerOf(1n)).to.equal(buyerOne.address);

    await expect(
      market.connect(buyerTwo).fillAsk(0, 1, { value: 100n })
    ).to.be.revertedWith('bad qty');
  });

  it('keeps failed native fee routing recoverable through pendingNative and flushNative', async function () {
    const [admin, seller, buyer] = await ethers.getSigners();
    const assetToken = await ethers.deployContract('MockERC721', ['Asset NFT', 'ANFT']);
    const revertingSplitter = await ethers.deployContract('MockSplitter', [true]);
    const workingSplitter = await ethers.deployContract('MockSplitter', [false]);
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, revertingSplitter.target, 500, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await assetToken.mint(seller.address);
    await assetToken.connect(seller).approve(market.target, 1n);

    await market.connect(seller).createAsk(
      {
        kind: 1,
        token: assetToken.target,
        id: 1n,
        nonceId: 0n,
        amount: 0n,
      },
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

    await market.connect(buyer).fillAsk(0, 1, { value: 100n });
    expect(await market.pendingNative()).to.equal(5n);

    await market.connect(admin).setFee(500, workingSplitter.target);
    await expect(market.connect(admin).flushNative(0)).to.not.be.reverted;

    expect(await market.pendingNative()).to.equal(0n);
    expect(await workingSplitter.nativeCalls()).to.equal(1n);
    expect(await workingSplitter.nativeReceived()).to.equal(5n);
  });

  it('settles escrowed ERC20 asks by releasing the market-held balance to the buyer', async function () {
    const [admin, seller, buyer] = await ethers.getSigners();
    const assetToken = await ethers.deployContract('MockERC20', ['Asset Token', 'ATK']);
    const splitter = await ethers.deployContract('MockSplitter', [false]);
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 0, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await assetToken.mint(seller.address, 10n);
    await assetToken.connect(seller).approve(market.target, 10n);

    await market.connect(seller).createAsk(
      {
        kind: 0,
        token: assetToken.target,
        id: 0n,
        nonceId: 0n,
        amount: 1n,
      },
      100n,
      ethers.ZeroAddress,
      10n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash
    );

    expect(await assetToken.balanceOf(market.target)).to.equal(10n);

    await expect(
      market.connect(buyer).fillAsk(0, 1, { value: 100n })
    ).to.emit(market, 'AskFilled');

    expect(await assetToken.balanceOf(buyer.address)).to.equal(1n);
    expect(await assetToken.balanceOf(market.target)).to.equal(9n);
  });

  it('emits RWA ledger for CS-01 canonical primary bond issuance', async function () {
    const [admin, issuerSpv, investorA, investorB, blockedInvestorC] = await ethers.getSigners();
    const bondToken = await ethers.deployContract('MockBondToken');
    const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const whitelist = await ethers.deployContract('MockWhitelist');
    const splitter = await ethers.deployContract('MockSplitter', [false]);
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 1000, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await market.setPaymentToken(paymentToken.target, true);
    await market.setWhitelist(whitelist.target);

    await whitelist.setWhitelisted(investorA.address, true);
    await whitelist.setWhitelisted(investorB.address, true);
    await whitelist.setWhitelisted(blockedInvestorC.address, false);

    await bondToken.mint(issuerSpv.address, 1n, 1n, 1001n);
    await bondToken.connect(issuerSpv).setApprovalForAll(market.target, true);

    await paymentToken.mint(investorA.address, 1_000_000n);
    await paymentToken.mint(investorB.address, 1_000_000n);
    await paymentToken.mint(blockedInvestorC.address, 1_000_000n);

    await paymentToken.connect(investorA).approve(market.target, 1_000_000n);
    await paymentToken.connect(investorB).approve(market.target, 1_000_000n);
    await paymentToken.connect(blockedInvestorC).approve(market.target, 1_000_000n);

    await market.connect(issuerSpv).createAsk(
      {
        kind: 3,
        token: bondToken.target,
        id: 1n,
        nonceId: 1n,
        amount: 1n,
      },
      1_000n,
      paymentToken.target,
      1_000n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash
    );

    await expect(
      market.connect(blockedInvestorC).fillAsk(0, 100n)
    ).to.be.revertedWith('KYCfail');

    await expect(market.connect(investorA).fillAsk(0, 600n)).to.emit(market, 'AskFilled');
    await expect(market.connect(investorB).fillAsk(0, 400n)).to.emit(market, 'AskFilled');

    expect(await bondToken.balanceOf(investorA.address, 1n, 1n)).to.equal(600n);
    expect(await bondToken.balanceOf(investorB.address, 1n, 1n)).to.equal(400n);
    expect(await splitter.erc20Received()).to.equal(100_000n);
    expect(await paymentToken.balanceOf(issuerSpv.address)).to.equal(900_000n);

    await market.connect(issuerSpv).createAsk(
      {
        kind: 3,
        token: bondToken.target,
        id: 1n,
        nonceId: 1n,
        amount: 1n,
      },
      1_000n,
      paymentToken.target,
      1n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash
    );

    await market.pause();
    await expect(market.connect(investorA).fillAsk(1, 1n)).to.be.reverted;

    emitRwaLedger({
      scenario: 'CS-01',
      source: 'market-manager',
      ledger: {
        investor_holdings: {
          investor_a: 600,
          investor_b: 400,
          blocked_investor_c: 0,
        },
        protocol_fee: 100000,
        market_paused_state: 'protected',
      },
      checks: {
        blocked_buy_rejected: true,
        pause_protected: true,
      },
    });
  });

  it('emits RWA ledger for CS-03 delegated secondary bond transfer', async function () {
    const [admin, investorA, investorB] = await ethers.getSigners();
    const bondToken = await ethers.deployContract('MockBondToken');
    const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const whitelist = await ethers.deployContract('MockWhitelist');
    const splitter = await ethers.deployContract('MockSplitter', [false]);
    const agreement = await ethers.deployContract('MockAgreementManager');
    const marketFactory = await ethers.getContractFactory('MarketManager');
    const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 1000, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'state-variable-immutable'],
    });
    await market.waitForDeployment();

    await market.setPaymentToken(paymentToken.target, true);
    await market.setWhitelist(whitelist.target);
    await whitelist.setWhitelisted(investorA.address, true);
    await whitelist.setWhitelisted(investorB.address, true);

    await bondToken.mint(investorA.address, 1n, 1n, 600n);
    await bondToken.mint(investorB.address, 1n, 1n, 400n);
    await bondToken.connect(investorA).setApprovalForAll(agreement.target, true);

    await paymentToken.mint(investorB.address, 500_000n);
    await paymentToken.connect(investorB).approve(market.target, 500_000n);

    const offerId = ethers.id('LOGISTICS-FACILITY-RENOVATION-SPV-BOND-SECONDARY-2026-01');

    await agreement.setOffer({
      issuer: investorA.address,
      investor: investorB.address,
      tokenAddress: bondToken.target,
      partition: ethers.ZeroHash,
      tokenId: 0n,
      classId: 1n,
      nonceId: 9n,
      amount: 200n,
      documentHash: ethers.ZeroHash,
      documentURI: 'ipfs://case-study-offer',
      expiry: 0n,
      nonce: 1n,
      delegatedTo: market.target,
      issuerSig: '0x',
      status: 1,
    });

    await expect(
      market.connect(investorA).createAsk(
        {
          kind: 3,
          token: bondToken.target,
          id: 1n,
          nonceId: 1n,
          amount: 1n,
        },
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
      )
    ).to.be.revertedWith('nonceId mismatch');

    await agreement.setOffer({
      issuer: investorA.address,
      investor: investorB.address,
      tokenAddress: bondToken.target,
      partition: ethers.ZeroHash,
      tokenId: 0n,
      classId: 1n,
      nonceId: 1n,
      amount: 200n,
      documentHash: ethers.ZeroHash,
      documentURI: 'ipfs://case-study-offer',
      expiry: 0n,
      nonce: 1n,
      delegatedTo: market.target,
      issuerSig: '0x',
      status: 1,
    });

    await market.connect(investorA).createAsk(
      {
        kind: 3,
        token: bondToken.target,
        id: 1n,
        nonceId: 1n,
        amount: 1n,
      },
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

    await expect(
      market.connect(investorB).fillAskWithSig(0, 100n, '0x1234')
    ).to.be.revertedWith('must buy full lot');

    await expect(
      market.connect(investorB).fillAskWithSig(0, 200n, '0x1234')
    ).to.emit(market, 'AskFilled');

    expect(await agreement.acceptCalls()).to.equal(1n);
    expect(await splitter.erc20Received()).to.equal(20_000n);
    expect(await paymentToken.balanceOf(investorA.address)).to.equal(180_000n);
    expect(await bondToken.balanceOf(investorA.address, 1n, 1n)).to.equal(400n);
    expect(await bondToken.balanceOf(investorB.address, 1n, 1n)).to.equal(600n);

    emitRwaLedger({
      scenario: 'CS-03',
      source: 'market-manager',
      ledger: {
        investor_holdings: {
          investor_a: 400,
          investor_b: 600,
        },
        protocol_fee: 20000,
      },
      checks: {
        delegated_metadata_mismatch_rejected: true,
        delegated_full_lot_enforced: true,
      },
    });
  });
});

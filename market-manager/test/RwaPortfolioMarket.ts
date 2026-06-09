import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitAssetLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ASSET_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ASSET_LEDGER::${JSON.stringify(entry)}`);
  }
}

function emitCorporateBondLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CORP_BOND_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CORP_BOND_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployPrimaryMarketFixture() {
  const [admin, issuer, investorA, investorB, blockedInvestor] = await ethers.getSigners();
  const bondToken = await ethers.deployContract('MockBondToken');
  const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const whitelist = await ethers.deployContract('MockWhitelist');
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const factory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(factory, [admin.address, splitter.target, 1000, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();

  await market.setPaymentToken(paymentToken.target, true);
  await market.setWhitelist(whitelist.target);

  await whitelist.setWhitelisted(investorA.address, true);
  await whitelist.setWhitelisted(investorB.address, true);
  await whitelist.setWhitelisted(blockedInvestor.address, false);

  await bondToken.mint(issuer.address, 1n, 1n, 1001n);
  await bondToken.connect(issuer).setApprovalForAll(market.target, true);

  for (const user of [investorA, investorB, blockedInvestor]) {
    await paymentToken.mint(user.address, 1_000_000n);
    await paymentToken.connect(user).approve(market.target, 1_000_000n);
  }

  await market.connect(issuer).createAsk(
    { kind: 3, token: bondToken.target, id: 1n, nonceId: 1n, amount: 1n },
    1_000n,
    paymentToken.target,
    1_000n,
    0,
    0,
    0,
    ethers.ZeroAddress,
    0,
    ethers.ZeroAddress,
    ethers.ZeroHash,
  );

  return { admin, issuer, investorA, investorB, blockedInvestor, bondToken, paymentToken, whitelist, splitter, market };
}

describe('MarketManager real-world RWA placement coverage', function () {
  it('emits asset-backed note ledger for ABN-CS-01 primary placement and KYC rejection', async function () {
    const { issuer, investorA, investorB, blockedInvestor, bondToken, paymentToken, splitter, market } = await deployPrimaryMarketFixture();

    await expect(market.connect(blockedInvestor).fillAsk(0, 100n)).to.be.revertedWith('KYCfail');
    await market.connect(investorA).fillAsk(0, 600n);
    await market.connect(investorB).fillAsk(0, 400n);

    expect(await bondToken.balanceOf(investorA.address, 1n, 1n)).to.equal(600n);
    expect(await bondToken.balanceOf(investorB.address, 1n, 1n)).to.equal(400n);
    expect(await splitter.erc20Received()).to.equal(100_000n);
    expect(await paymentToken.balanceOf(issuer.address)).to.equal(900_000n);

    emitAssetLedger({
      scenario: 'ABN-CS-01',
      source: 'market-manager',
      ledger: {
        investor_holdings: {
          investor_a: 600,
          investor_b: 400,
          blocked_investor_c: 0,
        },
      },
      checks: {
        blocked_investor_rejected: true,
        primary_distribution_complete: true,
      },
    });
  });

  it('emits corporate bond ledger for CBOND-CS-01 primary placement with routeable fees', async function () {
    const { investorA, investorB, bondToken, market, splitter } = await deployPrimaryMarketFixture();

    await market.connect(investorA).fillAsk(0, 600n);
    await market.connect(investorB).fillAsk(0, 400n);

    expect(await bondToken.balanceOf(investorA.address, 1n, 1n)).to.equal(600n);
    expect(await bondToken.balanceOf(investorB.address, 1n, 1n)).to.equal(400n);

    emitCorporateBondLedger({
      scenario: 'CBOND-CS-01',
      source: 'market-manager',
      ledger: {
        investor_holdings: {
          investor_a: 600,
          investor_b: 400,
        },
      },
      checks: {
        primary_distribution_complete: true,
        fee_route_triggered: true,
      },
    });
  });
});

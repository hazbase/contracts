import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployMarketFixture() {
  const [admin, rogue] = await ethers.getSigners();
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const marketFactory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 100, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();

  return { admin, rogue, market, paymentToken };
}

describe('MarketManager operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-01 market admin setter abuse rejection', async function () {
    const { rogue, market, paymentToken } = await deployMarketFixture();

    await expect(market.connect(rogue).setFee(100, rogue.address)).to.be.reverted;
    await expect(market.connect(rogue).setPaymentToken(paymentToken.target, true)).to.be.reverted;
    await expect(market.connect(rogue).setWhitelist(rogue.address)).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-01',
      source: 'market-manager',
      checks: {
        market_admin_setters_blocked: true,
      },
    });
  });

  it('emits role ledger for ROLE-04 rogue pauser blast radius limited to execution freeze', async function () {
    const { admin, rogue, market, paymentToken } = await deployMarketFixture();

    await market.grantRole(await market.PAUSER_ROLE(), rogue.address);
    await market.connect(rogue).pause();

    expect(await market.paused()).to.equal(true);
    await expect(market.connect(rogue).setFee(125, admin.address)).to.be.reverted;
    await expect(market.connect(rogue).setPaymentToken(paymentToken.target, false)).to.be.reverted;
    await expect(market.connect(rogue).setWhitelist(rogue.address)).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-04',
      source: 'market-manager',
      ledger: {
        market_paused_state: 'paused',
      },
      checks: {
        rogue_pauser_can_only_freeze_execution: true,
        rogue_pauser_cannot_mutate_financial_config: true,
      },
    });
  });
});

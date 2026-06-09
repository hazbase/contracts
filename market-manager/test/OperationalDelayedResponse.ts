import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitDelayLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_DELAY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_DELAY_LEDGER::${JSON.stringify(entry)}`);
  }
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

  await whitelist.setWhitelisted(buyer.address, true);
  await market.setWhitelist(whitelist.target);
  await market.setPaymentToken(paymentToken.target, true);

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

describe('MarketManager delayed-response coverage', function () {
  it('emits delay ledger for DELAY-01 open ask window before pause and explicit cleanup', async function () {
    const { seller, buyer, bondToken, market } = await deployBondAskFixture();

    await expect(market.connect(buyer).fillAsk(0, 50n)).to.emit(market, 'AskFilled');
    expect(await bondToken.balanceOf(buyer.address, 1n, 1n)).to.equal(50n);

    await market.pause();
    await expect(market.connect(seller).cancelAsk(0)).to.emit(market, 'AskCancelled');

    expect(await bondToken.balanceOf(seller.address, 1n, 1n)).to.equal(150n);
    await expect(market.connect(buyer).fillAsk(0, 10n)).to.be.reverted;

    emitDelayLedger({
      scenario: 'DELAY-01',
      source: 'market-manager',
      ledger: {
        market_paused_state: 'paused',
        quantity_filled_before_cleanup: 50,
        quantity_returned_after_cleanup: 150,
      },
      checks: {
        pre_cleanup_window_observed: true,
        cleanup_closed_remaining_state: true,
      },
    });
  });
});

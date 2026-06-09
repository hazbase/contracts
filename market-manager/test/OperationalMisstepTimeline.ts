import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitMisstepLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_MISSTEP_LEDGER_OUTPUT === '1') {
    console.log(`RWA_MISSTEP_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployBondAskFixture() {
  const [admin, seller, incidentBuyer, unaffectedBuyer] = await ethers.getSigners();
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
  await whitelist.setWhitelisted(incidentBuyer.address, true);
  await whitelist.setWhitelisted(unaffectedBuyer.address, true);

  await bondToken.mint(seller.address, 1n, 1n, 200n);
  await bondToken.connect(seller).setApprovalForAll(market.target, true);

  await paymentToken.mint(incidentBuyer.address, 300_000n);
  await paymentToken.connect(incidentBuyer).approve(market.target, 300_000n);
  await paymentToken.mint(unaffectedBuyer.address, 300_000n);
  await paymentToken.connect(unaffectedBuyer).approve(market.target, 300_000n);

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

  return { seller, incidentBuyer, unaffectedBuyer, bondToken, whitelist, market };
}

describe('MarketManager operator-misstep timeline coverage', function () {
  it('emits misstep ledger for MSTEP-01 wrong first revocation that leaves an ask live until pause and cancel', async function () {
    const { seller, incidentBuyer, unaffectedBuyer, bondToken, whitelist, market } = await deployBondAskFixture();

    await whitelist.setWhitelisted(incidentBuyer.address, false);
    await expect(market.connect(incidentBuyer).fillAsk(0, 10n)).to.be.revertedWith('KYCfail');
    await expect(market.connect(unaffectedBuyer).fillAsk(0, 50n)).to.emit(market, 'AskFilled');

    await market.pause();
    await expect(market.connect(seller).cancelAsk(0)).to.emit(market, 'AskCancelled');
    await expect(market.connect(unaffectedBuyer).fillAsk(0, 10n)).to.be.reverted;

    expect(await bondToken.balanceOf(unaffectedBuyer.address, 1n, 1n)).to.equal(50n);
    expect(await bondToken.balanceOf(seller.address, 1n, 1n)).to.equal(150n);

    emitMisstepLedger({
      scenario: 'MSTEP-01',
      source: 'market-manager',
      ledger: {
        wrong_first_action_state: 'buyer_revoked_but_ask_live',
        quantity_filled_after_wrong_action: 50,
        quantity_returned_after_recovery: 150,
      },
      checks: {
        wrong_first_action_left_remaining_execution_path: true,
        pause_and_cancel_closed_remaining_state: true,
      },
    });
  });
});

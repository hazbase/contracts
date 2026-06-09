import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitAmmLedger(entry: Record<string, unknown>) {
  if (process.env.AMM_LEDGER_OUTPUT === '1') {
    console.log(`AMM_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployAmm(baseFeeBps = 0, feeAlphaBps = 0) {
  const [admin, lp, trader] = await ethers.getSigners();
  const stable = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const rwa = await ethers.deployContract('MockERC20', ['RWA Share', 'RWS']);
  const splitter = await ethers.deployContract('MockSplitter');
  const ammFactory = await ethers.getContractFactory('CircuitBreakerAMM');
  const amm = await upgrades.deployProxy(
    ammFactory,
    [stable.target, rwa.target, splitter.target, baseFeeBps, feeAlphaBps, 5_000, 6_000, 9_900, 5_000, admin.address],
    {
      kind: 'uups',
      initializer: 'initialize',
    }
  );
  await amm.waitForDeployment();

  await stable.mint(lp.address, 2_000n);
  await rwa.mint(lp.address, 2_000n);
  await stable.mint(trader.address, 2_000n);
  await rwa.mint(trader.address, 2_000n);

  await stable.connect(lp).transfer(amm.target, 1_000n);
  await rwa.connect(lp).transfer(amm.target, 1_000n);
  await amm.connect(lp).mint(lp.address);

  await stable.connect(trader).approve(amm.target, 2_000n);
  await rwa.connect(trader).approve(amm.target, 2_000n);

  return { admin, lp, trader, stable, rwa, splitter, amm };
}

describe('CircuitBreakerAMM secondary-market coverage', function () {
  it('emits AMM ledger for AMM-CS-01 bootstrap and first discovery swap', async function () {
    const { trader, stable, rwa, splitter, amm } = await deployAmm(100, 0);

    expect(await amm.totalSupply()).to.equal(1_000n);
    expect(await amm.currentRV()).to.equal(0n);

    await ethers.provider.send('evm_increaseTime', [901]);
    await ethers.provider.send('evm_mine', []);

    const quote = await amm.quoteOut(200n, true);
    await expect(amm.connect(trader).swapExactToken0ForToken1(200n, 1n)).to.emit(amm, 'Swap');

    const reserves = await amm.getReserves();
    const stableBalanceAtPool = await stable.balanceOf(amm.target);
    const feeBufferStable = stableBalanceAtPool - reserves[0];

    expect(reserves[0]).to.equal(1_198n);
    expect(reserves[1]).to.equal(835n);
    expect(await amm.totalSupply()).to.equal(1_000n);
    expect(feeBufferStable).to.equal(2n);
    expect(await splitter.erc20Calls()).to.equal(1n);
    expect(await stable.balanceOf(trader.address)).to.equal(1_800n);
    expect(await rwa.balanceOf(trader.address)).to.equal(2_165n);

    emitAmmLedger({
      scenario: 'AMM-CS-01',
      source: 'circuitbreaker-amm',
      ledger: {
        pool_reserves: {
          stable: 1198,
          rwa: 835,
        },
        lp_supply: 1000,
        trader_balances: {
          stable: 1800,
          rwa: 2165,
        },
        fee_buffer_stable: 2,
        splitter_calls: 1,
        quote_out: Number(quote[0]),
        fee_bps: Number(quote[1]),
      },
      checks: {
        oracle_seeded_on_bootstrap: true,
        first_swap_price_discovery: true,
      },
    });
  });

  it('emits AMM ledger for AMM-CS-02 price shock and reverse-direction breaker', async function () {
    const { trader, stable, rwa, amm } = await deployAmm();

    await ethers.provider.send('evm_increaseTime', [901]);
    await ethers.provider.send('evm_mine', []);

    await expect(amm.connect(trader).swapExactToken0ForToken1(400n, 1n)).to.emit(amm, 'Swap');

    const rv = await amm.currentRV();
    expect(rv).to.equal(9580n);

    await expect(amm.connect(trader).swapExactToken1ForToken0(100n, 1n)).to.be.revertedWith('CB: paused');

    const reserves = await amm.getReserves();
    expect(reserves[0]).to.equal(1_400n);
    expect(reserves[1]).to.equal(715n);
    expect(await stable.balanceOf(trader.address)).to.equal(1_600n);
    expect(await rwa.balanceOf(trader.address)).to.equal(2_285n);

    emitAmmLedger({
      scenario: 'AMM-CS-02',
      source: 'circuitbreaker-amm',
      ledger: {
        pool_reserves: {
          stable: 1400,
          rwa: 715,
        },
        rv_bps: 9580,
        allowed_direction: 'stable_to_rwa_only',
        trader_balances: {
          stable: 1600,
          rwa: 2285,
        },
      },
      checks: {
        shock_swap_succeeds: true,
        reverse_swap_blocked: true,
      },
    });
  });
});

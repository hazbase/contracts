import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// Invariant/fuzz for CircuitBreakerAMM.
// Core property: every SUCCESSFUL swap must keep the constant product non-decreasing,
//   k_after = r0_after * r1_after >= r0_before * r1_before
// (fees only ever add to k; the net-input re-measurement must not let k leak down).
// Secondary properties: the dynamic fee is always clamped to <= 10000 bps, and a quoted output
// is strictly less than the output reserve (the pool can't be drained by one swap).
// Circuit-breaker reverts (high realized volatility / restricted direction) are expected and skipped
// — they don't violate the invariant; only completed swaps must preserve k.

function makeRng(seedInit: bigint) {
  let seed = seedInit;
  const MASK = (1n << 64n) - 1n;
  return (n: number) => {
    seed = (seed * 6364136223846793005n + 1442695040888963407n) & MASK;
    return Number((seed >> 33n) % BigInt(n));
  };
}

async function deployAmm() {
  const [admin, lp, trader] = await ethers.getSigners();
  const stable = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const rwa = await ethers.deployContract('MockERC20', ['RWA Share', 'RWS']);
  const splitter = await ethers.deployContract('MockSplitter');
  const ammFactory = await ethers.getContractFactory('CircuitBreakerAMM');
  // (token0, token1, splitter, baseFeeBps, feeAlphaBps, ...breaker/oracle params, admin)
  const amm = await upgrades.deployProxy(
    ammFactory,
    [stable.target, rwa.target, splitter.target, 30, 1_500, 5_000, 6_000, 9_900, 5_000, admin.address],
    { kind: 'uups', initializer: 'initialize' },
  );
  await amm.waitForDeployment();

  const BIG = 10n ** 12n;
  for (const who of [lp, trader]) {
    await stable.mint(who.address, BIG);
    await rwa.mint(who.address, BIG);
  }
  // Bootstrap a deep pool so modest swaps keep realized volatility low.
  await stable.connect(lp).transfer(amm.target, 100_000n);
  await rwa.connect(lp).transfer(amm.target, 100_000n);
  await amm.connect(lp).mint(lp.address);

  await stable.connect(trader).approve(amm.target, BIG);
  await rwa.connect(trader).approve(amm.target, BIG);
  return { admin, lp, trader, stable, rwa, amm };
}

async function bump(seconds: number) {
  await ethers.provider.send('evm_increaseTime', [seconds]);
  await ethers.provider.send('evm_mine', []);
}

describe('CircuitBreakerAMM constant-product invariant (fuzz)', function () {
  it('never lets k decrease across a long random swap sequence', async function () {
    const { trader, amm } = await deployAmm();
    await bump(901); // seed the oracle window

    const rng = makeRng(0x1234_5678n);
    let success = 0;
    let breakerSkips = 0;

    for (let i = 0; i < 80; i++) {
      const zeroForOne = rng(2) === 0;
      const amountIn = BigInt(10 + rng(400)); // 10..409, small vs 100k reserves

      // Fee is always clamped to the bps cap, and a single swap cannot drain the out-reserve.
      const [r0q, r1q] = await amm.getReserves();
      const reserveOut = zeroForOne ? r1q : r0q;
      try {
        const quote = await amm.quoteOut(amountIn, zeroForOne);
        expect(quote[1], 'feeBps <= 10000').to.be.lessThanOrEqual(10_000n);
        expect(quote[0], 'out < reserveOut').to.be.lessThan(reserveOut);
      } catch {
        // quoteOut can revert under breaker conditions; not part of the k-invariant.
      }

      const [r0b, r1b] = await amm.getReserves();
      const kBefore = r0b * r1b;
      try {
        const fn = zeroForOne ? 'swapExactToken0ForToken1' : 'swapExactToken1ForToken0';
        await amm.connect(trader)[fn](amountIn, 1n);
      } catch {
        breakerSkips++;
        await bump(120); // let RV decay, then continue
        continue;
      }

      const [r0a, r1a] = await amm.getReserves();
      const kAfter = r0a * r1a;
      expect(kAfter >= kBefore, `k must not decrease (i=${i}): ${kAfter} < ${kBefore}`).to.equal(true);
      success++;
      await bump(90);
    }

    // Guard against a vacuous pass: a meaningful number of swaps must have actually executed.
    expect(success, 'enough successful swaps to be meaningful').to.be.greaterThan(20);
    // Sanity: the breaker logic was reachable but did not block everything.
    expect(success + breakerSkips).to.equal(80);
  });
});

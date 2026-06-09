import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

// Invariant/fuzz for DebtManager.redeemDefaulted.
// Conservation property: when every holder of a DEFAULTED tranche burns their full balance, the
// pro-rata payouts (principalPool * amount / supply, recomputed per call) distribute the ENTIRE
// funded pool with nothing created and nothing frozen — sum(payouts) == funded pool, and the
// contract's principal balance ends at exactly 0, regardless of holder count, balance split,
// funding level, or redemption order.

const DAY = 86400n;
const COUPON_GRACE = 7n * DAY;

function makeRng(seedInit: bigint) {
  let seed = seedInit;
  const MASK = (1n << 64n) - 1n;
  return (n: number) => {
    seed = (seed * 6364136223846793005n + 1442695040888963407n) & MASK;
    return Number((seed >> 33n) % BigInt(n));
  };
}

async function nowTs() {
  return BigInt((await ethers.provider.getBlock('latest'))!.timestamp);
}

describe('DebtManager defaulted pro-rata conservation (fuzz)', function () {
  it('distributes exactly the funded pool across holders for many random configurations', async function () {
    const signers = await ethers.getSigners();
    const admin = signers[0];
    const rng = makeRng(0xc0ffeen);

    const TRIALS = 8;
    for (let t = 0; t < TRIALS; t++) {
      const snap = await ethers.deployContract('MockSnapshotDebtToken');
      const principal = await ethers.deployContract('MockCouponToken', ['Principal', 'PRN']);
      const coupon = await ethers.deployContract('MockCouponToken', ['Coupon', 'CPN']);
      const factory = await ethers.getContractFactory('DebtManager');
      const debt = await upgrades.deployProxy(factory, [admin.address, []], {
        kind: 'uups',
        initializer: 'initialize',
        unsafeAllow: ['constructor'],
      });
      await debt.waitForDeployment();

      // 2..4 holders with random balances; principalPerUnit = 1 so requiredPrincipal == totalSupply.
      const n = 2 + rng(3);
      const holders = signers.slice(1, 1 + n);
      const balances: bigint[] = [];
      let supply = 0n;
      for (let i = 0; i < n; i++) {
        const b = BigInt(10 + rng(990));
        balances.push(b);
        supply += b;
        await snap.mint(holders[i].address, 1n, 1n, b);
      }

      // Under-fund the pool to a random fraction of what is owed (still > 0).
      const pool = supply / 2n + BigInt(rng(Number(supply / 2n) + 1));
      await principal.mint(admin.address, pool);

      const now = await nowTs();
      const payDate = now + DAY;
      await debt.createTranche(
        snap.target, 1n, 1n, principal.target, 1n, coupon.target,
        now + 365n * DAY, 10_000, 10_000, 0, 0,
      );
      await debt.addCouponSchedule(0n, payDate, 500n); // activate

      await principal.approve(debt.target, pool);
      await debt.depositPrincipal(0n, pool);
      await mine(6); // clear noSameBlockFund window

      await time.increaseTo(Number(payDate + COUPON_GRACE + 1n));
      await debt.checkDefault(0n);
      expect((await debt.trancheInfo(0n))[7], `trial ${t} should be DEFAULTED`).to.equal(4n);

      // Redeem every holder's full balance in a shuffled order.
      const order = [...Array(n).keys()];
      for (let i = order.length - 1; i > 0; i--) {
        const j = rng(i + 1);
        [order[i], order[j]] = [order[j], order[i]];
      }
      for (const idx of order) {
        await debt.connect(holders[idx]).redeemDefaulted(0n, balances[idx]);
      }

      // Conservation: the whole funded pool was paid out, nothing remains frozen.
      let totalPaid = 0n;
      for (let i = 0; i < n; i++) {
        totalPaid += await principal.balanceOf(holders[i].address);
      }
      expect(totalPaid, `trial ${t}: payouts sum to the funded pool`).to.equal(pool);
      expect(
        await principal.balanceOf(debt.target),
        `trial ${t}: no principal left frozen in the contract`,
      ).to.equal(0n);
    }
  });
});

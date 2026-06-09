import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

// Coverage for DebtManager principal-recovery hardening:
//   redeemDefaulted — pro-rata recovery from an under-funded DEFAULTED pool.
//   closeTranche     — before SWEEP_GRACE only the surplus is swept; requiredPrincipal stays
//                           so MATURED holders can still redeemAtMaturity. After grace the whole
//                           (abandoned) pool may be swept.
//   exercisePut      — puts are blocked once the tranche leaves ACTIVE/PUT_NOTICE.

const DAY = 86400n;
const COUPON_GRACE = 7n * DAY;
const SWEEP_GRACE = 180n * DAY;

async function deploy() {
  const [admin, alice, bob, treasury] = await ethers.getSigners();
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
  return { admin, alice, bob, treasury, snap, principal, coupon, debt };
}

async function nowTs() {
  return BigInt((await ethers.provider.getBlock('latest'))!.timestamp);
}

// Create tranche (class/nonce 1/1) and activate it via addCouponSchedule.
async function createActiveTranche(
  debt: any,
  snap: any,
  principal: any,
  coupon: any,
  opts: { ppu: bigint; maturity: bigint; payDate: bigint; putBps?: bigint; putNoticeSec?: bigint },
) {
  await debt.createTranche(
    snap.target,
    1n,
    1n,
    principal.target,
    opts.ppu,
    coupon.target,
    opts.maturity,
    10_000, // callPriceBps
    opts.putBps ?? 10_000n, // putPriceBps
    0, // callNoticeSec
    opts.putNoticeSec ?? 0n, // putNoticeSec
  );
  await debt.addCouponSchedule(0n, opts.payDate, 500n); // PENDING -> ACTIVE
  return 0n;
}

describe('DebtManager principal recovery', function () {
  describe('redeemDefaulted pays a pro-rata share of an under-funded pool', function () {
    it('splits the remaining principal pool proportionally between holders', async function () {
      const { admin, alice, bob, snap, principal, coupon, debt } = await deploy();

      await snap.mint(alice.address, 1n, 1n, 60n);
      await snap.mint(bob.address, 1n, 1n, 40n); // totalSupply 100, requiredPrincipal = 10*100 = 1000
      await principal.mint(admin.address, 500n);

      const now = await nowTs();
      const payDate = now + DAY;
      const maturity = now + 365n * DAY;
      await createActiveTranche(debt, snap, principal, coupon, { ppu: 10n, maturity, payDate });

      // Fund only HALF of the required principal — the pool is genuinely under-funded.
      await principal.approve(debt.target, 500n);
      await debt.depositPrincipal(0n, 500n);
      await mine(6); // clear the noSameBlockFund window

      // Drive ACTIVE -> DEFAULTED (coupon unpaid past grace).
      await time.increaseTo(Number(payDate + COUPON_GRACE + 1n));
      await debt.checkDefault(0n);
      expect((await debt.trancheInfo(0n))[7]).to.equal(4n); // DEFAULTED

      // Pro-rata: alice 500*60/100 = 300, then bob 200*40/40 = 200. Whole pool fairly distributed.
      await debt.connect(alice).redeemDefaulted(0n, 60n);
      await debt.connect(bob).redeemDefaulted(0n, 40n);

      expect(await principal.balanceOf(alice.address)).to.equal(300n);
      expect(await principal.balanceOf(bob.address)).to.equal(200n);
      expect(await principal.balanceOf(debt.target)).to.equal(0n); // nothing frozen
    });

    it('rejects redeemDefaulted on a tranche that has not defaulted', async function () {
      const { admin, alice, snap, principal, coupon, debt } = await deploy();
      await snap.mint(alice.address, 1n, 1n, 10n);
      await principal.mint(admin.address, 100n);
      const now = await nowTs();
      await createActiveTranche(debt, snap, principal, coupon, {
        ppu: 10n,
        maturity: now + 365n * DAY,
        payDate: now + DAY,
      });
      // Fund + clear the noSameBlockFund window so the call reaches the status guard.
      await principal.approve(debt.target, 100n);
      await debt.depositPrincipal(0n, 100n);
      await mine(6);
      await expect(debt.connect(alice).redeemDefaulted(0n, 10n)).to.be.revertedWith('not defaulted');
    });
  });

  describe('closeTranche preserves holder principal before grace', function () {
    it('sweeps only the surplus and still lets a MATURED holder redeem', async function () {
      const { admin, alice, treasury, snap, principal, coupon, debt } = await deploy();

      await snap.mint(alice.address, 1n, 1n, 10n); // requiredPrincipal = 10*10 = 100
      await principal.mint(admin.address, 150n);

      const now = await nowTs();
      const maturity = now + 10n * DAY;
      const payDate = now + 5n * DAY;
      await createActiveTranche(debt, snap, principal, coupon, { ppu: 10n, maturity, payDate });

      await principal.approve(debt.target, 150n);
      await debt.depositPrincipal(0n, 150n); // pool 150, surplus 50 over the 100 owed
      await mine(6);

      // At/after maturity but well before maturity + SWEEP_GRACE.
      await time.increaseTo(Number(maturity + 1n));
      await debt.closeTranche(0n, treasury.address);

      // Only the 50 surplus is swept; the 100 owed to alice stays in the pool.
      expect(await principal.balanceOf(treasury.address)).to.equal(50n);
      expect((await debt.trancheInfo(0n))[7]).to.equal(5n); // MATURED

      // The holder can still redeem after closeTranche moved the tranche to MATURED.
      await debt.connect(alice).redeemAtMaturity(0n, 10n);
      expect(await principal.balanceOf(alice.address)).to.equal(100n);
      expect(await principal.balanceOf(debt.target)).to.equal(0n);
    });

    it('sweeps the entire (abandoned) pool only after maturity + SWEEP_GRACE', async function () {
      const { admin, treasury, alice, snap, principal, coupon, debt } = await deploy();

      await snap.mint(alice.address, 1n, 1n, 10n); // requiredPrincipal = 100
      await principal.mint(admin.address, 150n);

      const now = await nowTs();
      const maturity = now + 10n * DAY;
      const payDate = now + 5n * DAY;
      await createActiveTranche(debt, snap, principal, coupon, { ppu: 10n, maturity, payDate });

      await principal.approve(debt.target, 150n);
      await debt.depositPrincipal(0n, 150n);
      await mine(6);

      await time.increaseTo(Number(maturity + SWEEP_GRACE + 1n));
      await debt.closeTranche(0n, treasury.address);

      // After grace the full pool (including the abandoned principal) is swept.
      expect(await principal.balanceOf(treasury.address)).to.equal(150n);
      expect(await principal.balanceOf(debt.target)).to.equal(0n);
    });
  });

  describe('exercisePut is gated to live tranches', function () {
    it('lets a holder with an elapsed notice exercise while ACTIVE', async function () {
      const { admin, alice, snap, principal, coupon, debt } = await deploy();

      await snap.mint(alice.address, 1n, 1n, 10n); // requiredPrincipal = 100
      await principal.mint(admin.address, 100n);

      const now = await nowTs();
      await createActiveTranche(debt, snap, principal, coupon, {
        ppu: 10n,
        maturity: now + 365n * DAY,
        payDate: now + DAY,
        putBps: 10_000n,
        putNoticeSec: 0n,
      });

      await principal.approve(debt.target, 100n);
      await debt.depositPrincipal(0n, 100n);
      await mine(6);

      await debt.connect(alice).givePutNotice(0n);
      await debt.connect(alice).exercisePut(0n, 10n); // 100% put price -> 100
      expect(await principal.balanceOf(alice.address)).to.equal(100n);
    });

    it('blocks exercisePut once the tranche has DEFAULTED, even with a valid notice', async function () {
      const { admin, alice, snap, principal, coupon, debt } = await deploy();

      await snap.mint(alice.address, 1n, 1n, 10n);
      await principal.mint(admin.address, 100n);

      const now = await nowTs();
      const payDate = now + DAY;
      await createActiveTranche(debt, snap, principal, coupon, {
        ppu: 10n,
        maturity: now + 365n * DAY,
        payDate,
        putNoticeSec: 0n,
      });

      await principal.approve(debt.target, 100n);
      await debt.depositPrincipal(0n, 100n);
      await mine(6); // clear the noSameBlockFund window
      await debt.connect(alice).givePutNotice(0n); // filed while ACTIVE

      await time.increaseTo(Number(payDate + COUPON_GRACE + 1n));
      await debt.checkDefault(0n); // -> DEFAULTED

      await expect(debt.connect(alice).exercisePut(0n, 10n)).to.be.revertedWith('bad status');
    });
  });
});

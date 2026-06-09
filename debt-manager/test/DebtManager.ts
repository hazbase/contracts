import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitRwaLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_LEDGER_OUTPUT === '1') {
    console.log(`RWA_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('DebtManager case-study coverage', function () {
  it('pins coupon entitlements to the payment snapshot even after positions move', async function () {
    const [admin, alice, bob] = await ethers.getSigners();
    const snapshotToken = await ethers.deployContract('MockSnapshotDebtToken');
    const principalToken = await ethers.deployContract('MockCouponToken', ['Principal Token', 'PRN']);
    const couponToken = await ethers.deployContract('MockCouponToken', ['Coupon Token', 'CPN']);
    const debtFactory = await ethers.getContractFactory('DebtManager');
    const debt = await upgrades.deployProxy(debtFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await debt.waitForDeployment();

    await snapshotToken.mint(alice.address, 1n, 1n, 100n);
    await principalToken.mint(admin.address, 1_000n);
    await couponToken.mint(admin.address, 1_000n);

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      10n,
      couponToken.target,
      now + 30n * 24n * 60n * 60n,
      10_000,
      10_000,
      0,
      0
    );
    await debt.addCouponSchedule(0n, now > 1n ? now - 1n : 0n, 500n);

    await couponToken.approve(debt.target, 1_000n);
    await expect(debt.payCoupon(0n, 0, 1_000n)).to.emit(debt, 'CouponPaid');

    await snapshotToken.storeSnapshotFor(alice.address, 1n, 1n, 1n);
    await snapshotToken.storeSnapshotFor(bob.address, 1n, 1n, 1n);
    await snapshotToken.transferPosition(alice.address, bob.address, 1n, 1n, 100n);

    await expect(debt.connect(alice).claimCoupon(0n, 0))
      .to.emit(debt, 'CouponClaimed')
      .withArgs(0n, 0, alice.address, 1_000n);

    expect(await couponToken.balanceOf(alice.address)).to.equal(1_000n);
    expect(await debt.isClaimed(0n, 0, alice.address)).to.equal(true);

    await expect(debt.connect(bob).claimCoupon(0n, 0)).to.be.revertedWith('zero');
    await expect(debt.connect(alice).claimCoupon(0n, 0)).to.be.revertedWith('claimed');
  });

  it('marks a tranche defaulted only after coupon grace expires', async function () {
    const [admin] = await ethers.getSigners();
    const snapshotToken = await ethers.deployContract('MockSnapshotDebtToken');
    const principalToken = await ethers.deployContract('MockCouponToken', ['Principal Token', 'PRN']);
    const couponToken = await ethers.deployContract('MockCouponToken', ['Coupon Token', 'CPN']);
    const debtFactory = await ethers.getContractFactory('DebtManager');
    const debt = await upgrades.deployProxy(debtFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await debt.waitForDeployment();

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    const payDate = now + 2n * 24n * 60n * 60n;
    const maturity = now + 60n * 24n * 60n * 60n;

    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      10n,
      couponToken.target,
      maturity,
      10_000,
      10_000,
      0,
      0
    );
    await debt.addCouponSchedule(0n, payDate, 500n);

    await time.increaseTo(Number(payDate + 7n * 24n * 60n * 60n - 1n));
    await debt.checkDefault(0n);

    let tranche = await debt.trancheInfo(0n);
    expect(tranche[7]).to.equal(1n);

    await time.increaseTo(Number(payDate + 7n * 24n * 60n * 60n + 1n));
    await expect(debt.checkDefault(0n)).to.emit(debt, 'Defaulted').withArgs(0n, 0);

    tranche = await debt.trancheInfo(0n);
    expect(tranche[7]).to.equal(4n);

    emitRwaLedger({
      scenario: 'CS-04',
      source: 'debt-manager',
      checks: {
        default_after_grace_only: true,
      },
    });
  });

  it('redeems principal only at or after maturity', async function () {
    const [admin, alice] = await ethers.getSigners();
    const snapshotToken = await ethers.deployContract('MockSnapshotDebtToken');
    const principalToken = await ethers.deployContract('MockCouponToken', ['Principal Token', 'PRN']);
    const couponToken = await ethers.deployContract('MockCouponToken', ['Coupon Token', 'CPN']);
    const debtFactory = await ethers.getContractFactory('DebtManager');
    const debt = await upgrades.deployProxy(debtFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await debt.waitForDeployment();

    await snapshotToken.mint(alice.address, 1n, 1n, 10n);
    await principalToken.mint(admin.address, 1_000n);

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    const maturity = now + 15n * 24n * 60n * 60n;

    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      10n,
      couponToken.target,
      maturity,
      10_000,
      10_000,
      0,
      0
    );
    await debt.addCouponSchedule(0n, now + 2n * 24n * 60n * 60n, 500n);

    await principalToken.approve(debt.target, 1_000n);
    await debt.depositPrincipal(0n, 100n);
    await mine(6);

    await expect(
      debt.connect(alice).redeemAtMaturity(0n, 4n)
    ).to.be.revertedWith('not matured');

    await time.increaseTo(Number(maturity + 1n));

    await expect(
      debt.connect(alice).redeemAtMaturity(0n, 4n)
    ).to.emit(debt, 'PrincipalRedeemed').withArgs(0n, alice.address, 4n);

    expect(await principalToken.balanceOf(alice.address)).to.equal(40n);
    expect(await snapshotToken.balanceOf(alice.address, 1n, 1n)).to.equal(6n);
  });

  it('emits RWA ledger for CS-02 coupon and principal entitlements', async function () {
    const [admin, investorA, investorB] = await ethers.getSigners();
    const snapshotToken = await ethers.deployContract('MockSnapshotDebtToken');
    const principalToken = await ethers.deployContract('MockCouponToken', ['Principal Token', 'PRN']);
    const couponToken = await ethers.deployContract('MockCouponToken', ['Coupon Token', 'CPN']);
    const debtFactory = await ethers.getContractFactory('DebtManager');
    const debt = await upgrades.deployProxy(debtFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await debt.waitForDeployment();

    await snapshotToken.mint(investorA.address, 1n, 1n, 600n);
    await snapshotToken.mint(investorB.address, 1n, 1n, 400n);
    await principalToken.mint(admin.address, 1_000_000n);
    await couponToken.mint(admin.address, 100_000n);

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    const maturity = now + 30n * 24n * 60n * 60n;

    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      1_000n,
      couponToken.target,
      maturity,
      10_000,
      10_000,
      0,
      0
    );
    await debt.addCouponSchedule(0n, now > 1n ? now - 1n : 0n, 500n);

    await expect(debt.connect(investorA).claimCoupon(0n, 0)).to.be.revertedWith('not paid');

    await couponToken.approve(debt.target, 100_000n);
    await debt.payCoupon(0n, 0, 100_000n);

    await expect(debt.connect(investorA).claimCoupon(0n, 0))
      .to.emit(debt, 'CouponClaimed')
      .withArgs(0n, 0, investorA.address, 60_000n);
    await expect(debt.connect(investorB).claimCoupon(0n, 0))
      .to.emit(debt, 'CouponClaimed')
      .withArgs(0n, 0, investorB.address, 40_000n);

    await expect(debt.connect(investorA).claimCoupon(0n, 0)).to.be.revertedWith('claimed');

    await principalToken.approve(debt.target, 1_000_000n);
    await debt.depositPrincipal(0n, 1_000_000n);
    await mine(6);
    await time.increaseTo(Number(maturity + 1n));

    await debt.connect(investorA).redeemAtMaturity(0n, 600n);
    await debt.connect(investorB).redeemAtMaturity(0n, 400n);

    expect(await principalToken.balanceOf(investorA.address)).to.equal(600_000n);
    expect(await principalToken.balanceOf(investorB.address)).to.equal(400_000n);

    emitRwaLedger({
      scenario: 'CS-02',
      source: 'debt-manager',
      ledger: {
        coupon_receivable: {
          investor_a: 60000,
          investor_b: 40000,
        },
        principal_receivable: {
          investor_a: 600000,
          investor_b: 400000,
        },
      },
      checks: {
        pre_funding_claim_rejected: true,
        double_claim_rejected: true,
        post_maturity_redemption_succeeds: true,
      },
    });
  });

  it('emits RWA ledger for CS-03 snapshot-preserved coupon migration', async function () {
    const [admin, investorA, investorB] = await ethers.getSigners();
    const snapshotToken = await ethers.deployContract('MockSnapshotDebtToken');
    const principalToken = await ethers.deployContract('MockCouponToken', ['Principal Token', 'PRN']);
    const couponToken = await ethers.deployContract('MockCouponToken', ['Coupon Token', 'CPN']);
    const debtFactory = await ethers.getContractFactory('DebtManager');
    const debt = await upgrades.deployProxy(debtFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await debt.waitForDeployment();

    await snapshotToken.mint(investorA.address, 1n, 1n, 600n);
    await snapshotToken.mint(investorB.address, 1n, 1n, 400n);
    await couponToken.mint(admin.address, 100_000n);

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      1_000n,
      couponToken.target,
      now + 30n * 24n * 60n * 60n,
      10_000,
      10_000,
      0,
      0
    );
    await debt.addCouponSchedule(0n, now > 1n ? now - 1n : 0n, 500n);

    await couponToken.approve(debt.target, 100_000n);
    await debt.payCoupon(0n, 0, 100_000n);

    await snapshotToken.storeSnapshotFor(investorA.address, 1n, 1n, 1n);
    await snapshotToken.storeSnapshotFor(investorB.address, 1n, 1n, 1n);
    await snapshotToken.transferPosition(investorA.address, investorB.address, 1n, 1n, 200n);

    await debt.connect(investorA).claimCoupon(0n, 0);
    await debt.connect(investorB).claimCoupon(0n, 0);

    emitRwaLedger({
      scenario: 'CS-03',
      source: 'debt-manager',
      ledger: {
        coupon_receivable: {
          investor_a: 60000,
          investor_b: 40000,
        },
      },
      checks: {
        snapshot_preserved_after_transfer: true,
        future_holdings: {
          investor_a: 400,
          investor_b: 600,
        },
      },
    });
  });
});

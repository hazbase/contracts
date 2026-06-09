import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

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

async function deployDebtFixture() {
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
  await principalToken.mint(admin.address, 2_000_000n);
  await couponToken.mint(admin.address, 200_000n);

  return { admin, investorA, investorB, snapshotToken, principalToken, couponToken, debt };
}

describe('DebtManager real-world debt coverage', function () {
  it('emits asset-backed note ledger for ABN-CS-02 coupon servicing and partial amortization', async function () {
    const { admin, investorA, investorB, snapshotToken, principalToken, couponToken, debt } = await deployDebtFixture();

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      1_000n,
      couponToken.target,
      now + 90n * 24n * 60n * 60n,
      10_000,
      10_000,
      24n * 60n * 60n,
      0,
    );
    await debt.addCouponSchedule(0n, now > 1n ? now - 1n : 0n, 500n);

    await couponToken.approve(debt.target, 100_000n);
    await debt.payCoupon(0n, 0, 100_000n);
    await expect(debt.connect(investorA).claimCoupon(0n, 0)).to.emit(debt, 'CouponClaimed');
    await expect(debt.connect(investorB).claimCoupon(0n, 0)).to.emit(debt, 'CouponClaimed');

    await principalToken.approve(debt.target, 1_000_000n);
    await debt.depositPrincipal(0n, 1_000_000n);
    await mine(6);

    await debt.notifyCall(0n);
    await time.increase(24 * 60 * 60 + 1);
    await expect(debt.connect(investorA).executeCall(0n, 200n)).to.emit(debt, 'Called');
    await debt.notifySupplyChange(0n);

    expect(await snapshotToken.balanceOf(investorA.address, 1n, 1n)).to.equal(400n);
    expect(await snapshotToken.balanceOf(investorB.address, 1n, 1n)).to.equal(400n);
    expect(await principalToken.balanceOf(investorA.address)).to.equal(200_000n);
    expect(await couponToken.balanceOf(investorA.address)).to.equal(60_000n);
    expect(await couponToken.balanceOf(investorB.address)).to.equal(40_000n);

    emitAssetLedger({
      scenario: 'ABN-CS-02',
      source: 'debt-manager',
      ledger: {
        investor_holdings: {
          investor_a: 400,
          investor_b: 400,
        },
        coupon_receivable: {
          investor_a: 60000,
          investor_b: 40000,
        },
        principal_receivable: {
          investor_a: 200000,
          investor_b: 0,
        },
      },
      checks: {
        coupon_servicing_complete: true,
        partial_amortization_complete: true,
      },
    });
  });

  it('emits corporate bond ledger for CBOND-CS-02 coupon servicing and put-style retirement', async function () {
    const { admin, investorA, investorB, snapshotToken, principalToken, couponToken, debt } = await deployDebtFixture();

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    await debt.createTranche(
      snapshotToken.target,
      1n,
      1n,
      principalToken.target,
      1_000n,
      couponToken.target,
      now + 120n * 24n * 60n * 60n,
      10_000,
      10_000,
      0,
      24n * 60n * 60n,
    );
    await debt.addCouponSchedule(0n, now > 1n ? now - 1n : 0n, 350n);

    await couponToken.approve(debt.target, 50_000n);
    await debt.payCoupon(0n, 0, 50_000n);
    await debt.connect(investorA).claimCoupon(0n, 0);
    await debt.connect(investorB).claimCoupon(0n, 0);

    await principalToken.approve(debt.target, 1_000_000n);
    await debt.depositPrincipal(0n, 1_000_000n);
    await mine(6);

    await debt.connect(investorB).givePutNotice(0n);
    await time.increase(24 * 60 * 60 + 1);
    await expect(debt.connect(investorB).exercisePut(0n, 150n)).to.emit(debt, 'PutExecuted');
    await debt.notifySupplyChange(0n);

    expect(await snapshotToken.balanceOf(investorB.address, 1n, 1n)).to.equal(250n);
    expect(await principalToken.balanceOf(investorB.address)).to.equal(150_000n);

    emitCorporateBondLedger({
      scenario: 'CBOND-CS-02',
      source: 'debt-manager',
      ledger: {
        coupon_receivable: {
          investor_a: 30000,
          investor_b: 20000,
        },
        principal_receivable: {
          investor_a: 0,
          investor_b: 150000,
        },
        investor_holdings: {
          investor_a: 600,
          investor_b: 250,
        },
      },
      checks: {
        coupon_servicing_complete: true,
        tender_style_retirement_complete: true,
      },
    });
  });

  it('emits corporate bond ledger for CBOND-CS-05 defaulted tranche restricting normal redemption', async function () {
    const { admin, investorA, snapshotToken, principalToken, couponToken, debt } = await deployDebtFixture();

    const latest = await ethers.provider.getBlock('latest');
    const now = BigInt(latest!.timestamp);
    const payDate = now + 2n * 24n * 60n * 60n;
    const maturity = payDate + 12n * 24n * 60n * 60n;

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
      0,
    );
    await debt.addCouponSchedule(0n, payDate, 500n);

    await principalToken.approve(debt.target, 1_000_000n);
    await debt.depositPrincipal(0n, 1_000_000n);
    await mine(6);

    await time.increaseTo(Number(payDate + 7n * 24n * 60n * 60n + 1n));
    await debt.checkDefault(0n);
    await time.increaseTo(Number(maturity + 1n));

    await expect(debt.connect(investorA).redeemAtMaturity(0n, 100n)).to.be.revertedWith('bad status');

    emitCorporateBondLedger({
      scenario: 'CBOND-CS-05',
      source: 'debt-manager',
      ledger: {
        default_state: 'defaulted',
      },
      checks: {
        unresolved_default_blocks_normal_redemption: true,
      },
    });
  });
});

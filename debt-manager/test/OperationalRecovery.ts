import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitOpsLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_OPS_LEDGER_OUTPUT === '1') {
    console.log(`RWA_OPS_LEDGER::${JSON.stringify(entry)}`);
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

describe('DebtManager operational recovery coverage', function () {
  it('emits ops ledger for OPS-REC-02 tender-style retirement under stress', async function () {
    const { investorA, investorB, snapshotToken, principalToken, couponToken, debt } = await deployDebtFixture();

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
    await debt.addCouponSchedule(0n, now + 24n * 60n * 60n, 350n);

    await principalToken.approve(debt.target, 1_000_000n);
    await debt.depositPrincipal(0n, 1_000_000n);
    await mine(6);

    await debt.connect(investorB).givePutNotice(0n);
    await time.increase(24 * 60 * 60 + 1);
    await expect(debt.connect(investorB).exercisePut(0n, 150n)).to.emit(debt, 'PutExecuted');
    await debt.notifySupplyChange(0n);

    expect(await snapshotToken.balanceOf(investorA.address, 1n, 1n)).to.equal(600n);
    expect(await snapshotToken.balanceOf(investorB.address, 1n, 1n)).to.equal(250n);
    expect(await principalToken.balanceOf(investorB.address)).to.equal(150_000n);

    emitOpsLedger({
      scenario: 'OPS-REC-02',
      source: 'debt-manager',
      ledger: {
        investor_holdings: {
          investor_a: 600,
          investor_b: 250,
        },
        principal_receivable: {
          investor_b: 150000,
        },
        outstanding_supply_after_retirement: 850,
      },
      checks: {
        put_notice_exercised: true,
        retirement_reconciled: true,
      },
    });
  });

  it('emits ops ledger for OPS-REC-03 defaulted tranche blocks ordinary redemption', async function () {
    const { investorA, snapshotToken, principalToken, couponToken, debt } = await deployDebtFixture();

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

    emitOpsLedger({
      scenario: 'OPS-REC-03',
      source: 'debt-manager',
      ledger: {
        default_state: 'defaulted',
      },
      checks: {
        default_triggered: true,
        ordinary_redemption_blocked: true,
      },
    });
  });
});

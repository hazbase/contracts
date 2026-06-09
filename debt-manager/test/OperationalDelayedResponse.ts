import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitDelayLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_DELAY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_DELAY_LEDGER::${JSON.stringify(entry)}`);
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

  return { investorA, snapshotToken, principalToken, couponToken, debt };
}

describe('DebtManager delayed-response coverage', function () {
  it('emits delay ledger for DELAY-03 grace window before default and later redemption block', async function () {
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

    await time.increaseTo(Number(payDate + 7n * 24n * 60n * 60n - 1n));
    await debt.checkDefault(0n);
    expect((await debt.trancheInfo(0n))[7]).to.equal(1n);

    await time.increaseTo(Number(payDate + 7n * 24n * 60n * 60n + 1n));
    await debt.checkDefault(0n);
    expect((await debt.trancheInfo(0n))[7]).to.equal(4n);

    await time.increaseTo(Number(maturity + 1n));
    await expect(debt.connect(investorA).redeemAtMaturity(0n, 100n)).to.be.revertedWith('bad status');

    emitDelayLedger({
      scenario: 'DELAY-03',
      source: 'debt-manager',
      ledger: {
        default_state: 'defaulted_after_grace',
      },
      checks: {
        pre_grace_default_blocked: true,
        post_grace_default_triggered: true,
        redemption_blocked_after_default: true,
      },
    });
  });
});

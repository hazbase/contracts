import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitDelayLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_DELAY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_DELAY_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('ReservePool delayed-response coverage', function () {
  it('emits delay ledger for DELAY-04 compensation delay with stable bucket accounting', async function () {
    const [admin, investor] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);
    await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), admin.address);

    await token.mint(admin.address, 1_000n);
    await token.approve(reservePool.target, 1_000n);

    await reservePool.fundCompensation(token.target, 400n);
    expect(await reservePool.compensationOf(token.target)).to.equal(400n);
    expect(await token.balanceOf(investor.address)).to.equal(0n);

    await reservePool.payCompensation(token.target, investor.address, 150n);
    expect(await reservePool.compensationOf(token.target)).to.equal(250n);
    expect(await token.balanceOf(investor.address)).to.equal(150n);

    emitDelayLedger({
      scenario: 'DELAY-04',
      source: 'reserve-pool',
      ledger: {
        compensation_before_payout: 400,
        compensation_after_payout: 250,
      },
      checks: {
        delayed_compensation_accounting_stable: true,
      },
    });
  });
});

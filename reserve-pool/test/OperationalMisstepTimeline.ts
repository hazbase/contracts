import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitMisstepLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_MISSTEP_LEDGER_OUTPUT === '1') {
    console.log(`RWA_MISSTEP_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('ReservePool operator-misstep timeline coverage', function () {
  it('emits misstep ledger for MSTEP-03 compensation attempted before sweep and recovered after bucket reallocation', async function () {
    const [admin, investor] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);
    await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), admin.address);

    await token.mint(admin.address, 2_000n);
    await token.approve(reservePool.target, 2_000n);

    await reservePool.fundLiquidity(token.target, 800n);
    await reservePool.fundCompensation(token.target, 100n);

    await expect(reservePool.payCompensation(token.target, investor.address, 250n)).to.be.revertedWith('exceeds compensation reserve');
    await reservePool.sweep(token.target, 200n, true);
    await expect(reservePool.payCompensation(token.target, investor.address, 250n)).to.emit(reservePool, 'CompensationPaid');

    expect(await reservePool.liquidityOf(token.target)).to.equal(600n);
    expect(await reservePool.compensationOf(token.target)).to.equal(50n);
    expect(await token.balanceOf(investor.address)).to.equal(250n);

    emitMisstepLedger({
      scenario: 'MSTEP-03',
      source: 'reserve-pool',
      ledger: {
        compensation_before_reallocation: 100,
        reserve_liquidity_after_reallocation: 600,
        compensation_after_recovery: 50,
      },
      checks: {
        premature_compensation_rejected: true,
        sweep_then_compensate_recovered_path: true,
      },
    });
  });
});

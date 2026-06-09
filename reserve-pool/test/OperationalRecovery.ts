import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitOpsLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_OPS_LEDGER_OUTPUT === '1') {
    console.log(`RWA_OPS_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('ReservePool operational recovery coverage', function () {
  it('emits ops ledger for OPS-REC-03 reserve sweep and compensation after default', async function () {
    const [admin, investor] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);
    await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), admin.address);

    await token.mint(admin.address, 2_000n);
    await token.approve(reservePool.target, 2_000n);

    await reservePool.fundLiquidity(token.target, 900n);
    await reservePool.fundCompensation(token.target, 300n);
    await reservePool.sweep(token.target, 100n, true);
    await expect(reservePool.payCompensation(token.target, investor.address, 250n)).to.emit(reservePool, 'CompensationPaid');

    expect(await reservePool.liquidityOf(token.target)).to.equal(800n);
    expect(await reservePool.compensationOf(token.target)).to.equal(150n);
    expect(await token.balanceOf(investor.address)).to.equal(250n);

    emitOpsLedger({
      scenario: 'OPS-REC-03',
      source: 'reserve-pool',
      ledger: {
        reserve_liquidity: 800,
        reserve_compensation: 150,
      },
      checks: {
        compensation_reconciled: true,
      },
    });
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('ReservePool configuration-hazard coverage', function () {
  it('emits config ledger for CFG-05 cooldown and bucket intent drift edges', async function () {
    const [admin] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);
    await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), admin.address);

    await token.mint(admin.address, 1_000n);
    await token.approve(reservePool.target, 1_000n);

    await reservePool.fundLiquidity(token.target, 600n);
    await reservePool.fundCompensation(token.target, 200n);
    await expect(reservePool.setBuyBackCooldown(0)).to.be.revertedWith('invalid cooldown');

    await reservePool.sweep(token.target, 150n, true);
    expect(await reservePool.liquidityOf(token.target)).to.equal(450n);
    expect(await reservePool.compensationOf(token.target)).to.equal(350n);

    emitConfigLedger({
      scenario: 'CFG-05',
      source: 'reserve-pool',
      ledger: {
        reserve_liquidity: 450,
        reserve_compensation: 350,
        reserve_config_state: 'bucket_intent_shifted',
      },
      checks: {
        invalid_cooldown_rejected: true,
        bucket_intent_drift_visible: true,
      },
    });
  });
});

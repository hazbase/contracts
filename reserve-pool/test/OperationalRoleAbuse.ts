import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployReserveFixture() {
  const [admin, royalty, guardian, breaker, pauser, outsider] = await ethers.getSigners();
  const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
  const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

  await reservePool.waitForDeployment();
  await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), royalty.address);
  await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), guardian.address);
  await reservePool.grantRole(await reservePool.CIRCUIT_BREAKER_ROLE(), breaker.address);
  await reservePool.grantRole(await reservePool.PAUSER_ROLE(), pauser.address);

  return { admin, royalty, guardian, breaker, pauser, outsider, reservePool, token };
}

describe('ReservePool operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-02 reserve role-separation matrix', async function () {
    const { royalty, guardian, breaker, pauser, outsider, reservePool, token } = await deployReserveFixture();

    await expect(reservePool.connect(royalty).setBuyBackCooldown(3600)).to.be.reverted;
    await expect(reservePool.connect(guardian).fundLiquidity(token.target, 1n)).to.be.reverted;
    await expect(reservePool.connect(breaker).sweep(token.target, 1n, true)).to.be.reverted;
    await expect(reservePool.connect(pauser).payCompensation(token.target, outsider.address, 1n)).to.be.reverted;
    await expect(reservePool.connect(royalty).triggerBuyBack(token.target, 1n, 0n, [])).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-02',
      source: 'reserve-pool',
      ledger: {
        reserve_role_matrix: 'separated',
      },
      checks: {
        royalty_cannot_guardian_actions: true,
        guardian_cannot_royalty_actions: true,
        circuit_breaker_cannot_guardian_actions: true,
        pauser_cannot_financial_actions: true,
      },
    });
  });

  it('emits role ledger for ROLE-04 reserve pauser blast radius limited to pause only', async function () {
    const { pauser, outsider, reservePool, token } = await deployReserveFixture();

    await reservePool.connect(pauser).pause();
    expect(await reservePool.paused()).to.equal(true);

    await expect(reservePool.connect(pauser).sweep(token.target, 1n, true)).to.be.reverted;
    await expect(reservePool.connect(pauser).payCompensation(token.target, outsider.address, 1n)).to.be.reverted;
    await expect(reservePool.connect(pauser).setBuyBackCooldown(7200)).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-04',
      source: 'reserve-pool',
      ledger: {
        reserve_paused_state: 'paused',
      },
      checks: {
        reserve_pauser_cannot_move_funds: true,
        reserve_pauser_cannot_change_recovery_config: true,
      },
    });
  });
});

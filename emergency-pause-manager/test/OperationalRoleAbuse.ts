import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('EmergencyPauseManager operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-03 pause topology abuse rejection and split recovery', async function () {
    const [admin, guardian, governor, outsider] = await ethers.getSigners();
    const managerFactory = await ethers.getContractFactory('EmergencyPauseManager');
    const manager = await upgrades.deployProxy(managerFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await manager.waitForDeployment();

    const bondTransfer = await ethers.deployContract('MockPausableTarget', [false, false]);
    const marketFill = await ethers.deployContract('MockPausableTarget', [false, false]);

    await manager.grantRole(await manager.GUARDIAN_ROLE(), guardian.address);
    await manager.grantRole(await manager.GOVERNOR_ROLE(), governor.address);

    await expect(manager.connect(outsider).registerPausable(bondTransfer.target)).to.be.reverted;
    await manager.registerPausable(bondTransfer.target);
    await manager.registerPausable(marketFill.target);
    await expect(manager.connect(outsider).removePausable(bondTransfer.target)).to.be.reverted;
    await expect(manager.connect(outsider).pauseAll()).to.be.reverted;
    await expect(manager.connect(outsider).unpauseAll()).to.be.reverted;

    await manager.connect(guardian).pauseAll();
    expect(await bondTransfer.paused()).to.equal(true);
    expect(await marketFill.paused()).to.equal(true);

    await expect(manager.connect(guardian).unpauseAll()).to.be.reverted;
    await manager.connect(governor).unpauseAll();
    expect(await bondTransfer.paused()).to.equal(false);
    expect(await marketFill.paused()).to.equal(false);

    emitRoleLedger({
      scenario: 'ROLE-03',
      source: 'emergency-pause-manager',
      ledger: {
        pause_topology_state: 'guardian_pause_governor_unpause',
      },
      checks: {
        unauthorized_topology_mutation_blocked: true,
        unauthorized_pause_unpause_blocked: true,
        split_recovery_confirmed: true,
      },
    });
  });
});

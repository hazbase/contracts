import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitGovernanceLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_GOV_LEDGER_OUTPUT === '1') {
    console.log(`RWA_GOV_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('EmergencyPauseManager internal coverage', function () {
  it('pauses and unpauses registered targets while isolating failures', async function () {
    const [admin, guardian, governor] = await ethers.getSigners();
    const managerFactory = await ethers.getContractFactory('EmergencyPauseManager');
    const manager = await upgrades.deployProxy(managerFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await manager.waitForDeployment();

    const healthy = await ethers.deployContract('MockPausableTarget', [false, false]);
    const flaky = await ethers.deployContract('MockPausableTarget', [true, true]);

    await manager.grantRole(await manager.GUARDIAN_ROLE(), guardian.address);
    await manager.grantRole(await manager.GOVERNOR_ROLE(), governor.address);

    await expect(manager.registerPausable(manager.target)).to.be.revertedWith('cannot self-register');

    await manager.registerPausable(healthy.target);
    await manager.registerPausable(flaky.target);

    await expect(manager.connect(guardian).pauseAll())
      .to.emit(manager, 'PauseFailed')
      .withArgs(flaky.target);

    expect(await healthy.paused()).to.equal(true);
    expect(await flaky.paused()).to.equal(false);
    expect(await manager.checkAllPaused()).to.equal(false);

    await flaky.setFailures(false, true);

    await expect(manager.connect(governor).unpauseAll())
      .to.emit(manager, 'UnpauseFailed')
      .withArgs(flaky.target);

    expect(await healthy.paused()).to.equal(false);
    expect(await flaky.paused()).to.equal(false);

    await flaky.setFailures(false, false);
    await manager.connect(guardian).pauseAll();
    expect(await manager.checkAllPaused()).to.equal(true);

    emitGovernanceLedger({
      scenario: 'GOV-CS-01',
      source: 'emergency-pause-manager',
      ledger: {
        registered_targets: 2,
        paused_state_after_partial_pause: {
          healthy: true,
          flaky: false,
        },
        paused_state_after_recovery: {
          healthy: true,
          flaky: true,
        },
        check_all_paused: true,
      },
      checks: {
        self_registration_blocked: true,
        partial_pause_failure_isolated: true,
        batch_unpause_failure_isolated: true,
        all_paused_after_recovery: true,
      },
    });
  });
});

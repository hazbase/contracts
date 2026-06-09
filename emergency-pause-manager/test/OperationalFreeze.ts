import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

describe('EmergencyPauseManager operational freeze coverage', function () {
  it('supports explicit selective recovery after a coordinated freeze drill', async function () {
    const [admin, guardian, governor] = await ethers.getSigners();
    const managerFactory = await ethers.getContractFactory('EmergencyPauseManager');
    const manager = await upgrades.deployProxy(managerFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await manager.waitForDeployment();

    const bondTransfer = await ethers.deployContract('MockPausableTarget', [false, false]);
    const marketFill = await ethers.deployContract('MockPausableTarget', [false, false]);
    const agreementAccept = await ethers.deployContract('MockPausableTarget', [false, false]);

    await manager.grantRole(await manager.GUARDIAN_ROLE(), guardian.address);
    await manager.grantRole(await manager.GOVERNOR_ROLE(), governor.address);

    await manager.registerPausable(bondTransfer.target);
    await manager.registerPausable(marketFill.target);
    await manager.registerPausable(agreementAccept.target);

    await manager.connect(guardian).pauseAll();
    expect(await bondTransfer.paused()).to.equal(true);
    expect(await marketFill.paused()).to.equal(true);
    expect(await agreementAccept.paused()).to.equal(true);
    expect(await manager.checkAllPaused()).to.equal(true);

    await manager.removePausable(agreementAccept.target);
    await manager.connect(governor).unpauseAll();

    expect(await bondTransfer.paused()).to.equal(false);
    expect(await marketFill.paused()).to.equal(false);
    expect(await agreementAccept.paused()).to.equal(true);

    await manager.registerPausable(agreementAccept.target);
    await manager.connect(governor).unpauseAll();
    expect(await agreementAccept.paused()).to.equal(false);
  });
});

import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

describe('HAZAMA governance migration', function () {
  it('moves administration behind a delay and keeps emergency control pause-only', async function () {
    const [legacyAdmin, governanceMultisig, emergencyMultisig, publicExecutor] =
      await ethers.getSigners();

    const manager = await ethers.deployContract('GenericRwaBackingLockManager', [
      legacyAdmin.address,
    ]);
    await manager.waitForDeployment();
    const finalizer = await ethers.deployContract('HazamaRwaReleaseFinalizerV2', [
      legacyAdmin.address,
      await manager.getAddress(),
      300n,
    ]);
    await finalizer.waitForDeployment();

    const approverA = ethers.Wallet.createRandom();
    const approverB = ethers.Wallet.createRandom();
    await finalizer.setHazamaApprover(approverA.address, true);
    await finalizer.setHazamaApprover(approverB.address, true);
    await finalizer.setHazamaThreshold(2n);
    await finalizer.unpause();

    const delay = 3600n;
    const timelock = await ethers.deployContract('HazamaGovernanceTimelock', [
      delay,
      [governanceMultisig.address],
      [ethers.ZeroAddress],
      ethers.ZeroAddress,
    ]);
    await timelock.waitForDeployment();
    const pauseGuard = await ethers.deployContract('HazamaEmergencyPauseGuard', [
      await timelock.getAddress(),
      emergencyMultisig.address,
      [await finalizer.getAddress()],
    ]);
    await pauseGuard.waitForDeployment();

    const defaultAdminRole = await finalizer.DEFAULT_ADMIN_ROLE();
    const pauserRole = await finalizer.PAUSER_ROLE();
    const approverAdminRole = await finalizer.HAZAMA_APPROVER_ADMIN_ROLE();
    await finalizer.grantRole(defaultAdminRole, await timelock.getAddress());
    await finalizer.grantRole(pauserRole, await timelock.getAddress());
    await finalizer.grantRole(pauserRole, await pauseGuard.getAddress());
    await finalizer.grantRole(approverAdminRole, await timelock.getAddress());
    await finalizer.revokeRole(approverAdminRole, legacyAdmin.address);
    await finalizer.revokeRole(pauserRole, legacyAdmin.address);
    await finalizer.revokeRole(defaultAdminRole, legacyAdmin.address);

    await expect(finalizer.connect(legacyAdmin).setHazamaThreshold(1n)).to.be.reverted;
    await expect(finalizer.connect(emergencyMultisig).unpause()).to.be.reverted;

    await expect(pauseGuard.connect(emergencyMultisig).pause(await finalizer.getAddress()))
      .to.emit(pauseGuard, 'EmergencyPauseExecuted')
      .withArgs(await finalizer.getAddress(), emergencyMultisig.address);
    expect(await finalizer.paused()).to.equal(true);

    const unpauseData = finalizer.interface.encodeFunctionData('unpause');
    const predecessor = ethers.ZeroHash;
    const salt = ethers.id('hazama-governance-unpause-test');
    await timelock.connect(governanceMultisig).schedule(
      await finalizer.getAddress(),
      0n,
      unpauseData,
      predecessor,
      salt,
      delay,
    );
    await expect(
      timelock.connect(publicExecutor).execute(
        await finalizer.getAddress(),
        0n,
        unpauseData,
        predecessor,
        salt,
      ),
    ).to.be.reverted;
    await time.increase(delay);
    await timelock.connect(publicExecutor).execute(
      await finalizer.getAddress(),
      0n,
      unpauseData,
      predecessor,
      salt,
    );
    expect(await finalizer.paused()).to.equal(false);

    const thresholdData = finalizer.interface.encodeFunctionData('setHazamaThreshold', [1n]);
    const thresholdSalt = ethers.id('hazama-governance-threshold-test');
    await timelock.connect(governanceMultisig).schedule(
      await finalizer.getAddress(),
      0n,
      thresholdData,
      predecessor,
      thresholdSalt,
      delay,
    );
    await time.increase(delay);
    await timelock.connect(publicExecutor).execute(
      await finalizer.getAddress(),
      0n,
      thresholdData,
      predecessor,
      thresholdSalt,
    );
    expect(await finalizer.hazamaThreshold()).to.equal(1n);
  });
});

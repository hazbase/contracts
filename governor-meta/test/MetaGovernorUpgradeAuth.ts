import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// MetaGovernor never runs the base Governor.execute() flow (it finalizes by scheduling
// directly on the timelock), so the default _checkGovernance — which pops the _governanceCall
// deque — would ALWAYS revert when the timelock calls back into an onlyGovernance function,
// permanently bricking upgrades / relay / updateForwarder. The fix authorizes the executor
// (timelock) by msg.sender instead. These tests prove BOTH halves:
//   (1) a direct external caller is rejected, and
//   (2) the same call routed through the timelock executor succeeds.

async function deployTimelock(admin: string) {
  const TL = await ethers.getContractFactory('TimelockControllerUpgradeable');
  const tl = await TL.deploy();
  await tl.waitForDeployment();
  // minDelay 0, proposer = executor = admin, admin = admin
  await tl.initialize(0, [admin], [admin], admin);
  return tl;
}

async function deployGovernor(admin: string, econ: string, soc: string, timelock: string) {
  const factory = await ethers.getContractFactory('MetaGovernor');
  const gov = await upgrades.deployProxy(
    factory,
    [admin, 'Meta', econ, soc, timelock, []],
    { kind: 'uups', initializer: 'initialize' },
  );
  await gov.waitForDeployment();
  return gov;
}

describe('MetaGovernor governance-only authorization through the timelock', function () {
  let admin: any, econ: any, soc: any, outsider: any, forwarder: any;
  let tl: any, gov: any, govAddr: string, tlAddr: string;

  // Schedule + execute a call to the governor via the timelock executor.
  async function execViaTimelock(data: string, salt: string) {
    await tl.schedule(govAddr, 0, data, ethers.ZeroHash, salt, 0);
    await tl.execute(govAddr, 0, data, ethers.ZeroHash, salt);
  }

  beforeEach(async function () {
    [admin, econ, soc, outsider, forwarder] = await ethers.getSigners();
    tl = await deployTimelock(admin.address);
    tlAddr = await tl.getAddress();
    gov = await deployGovernor(admin.address, econ.address, soc.address, tlAddr);
    govAddr = await gov.getAddress();
  });

  describe('updateForwarder (onlyGovernance)', function () {
    it('rejects a direct external caller with onlyExecutor', async function () {
      await expect(
        gov.connect(outsider).updateForwarder(forwarder.address, true),
      ).to.be.revertedWith('Governor: onlyExecutor');
    });

    it('rejects even the admin calling directly (authority is the executor, not a role)', async function () {
      await expect(
        gov.connect(admin).updateForwarder(forwarder.address, true),
      ).to.be.revertedWith('Governor: onlyExecutor');
    });

    it('succeeds when routed through the timelock executor (the path the default check would brick)', async function () {
      expect(await gov.isTrustedForwarder(forwarder.address)).to.equal(false);

      const data = gov.interface.encodeFunctionData('updateForwarder', [forwarder.address, true]);
      await execViaTimelock(data, ethers.id('add-forwarder'));

      expect(await gov.isTrustedForwarder(forwarder.address)).to.equal(true);

      // ...and it can be revoked the same way.
      const off = gov.interface.encodeFunctionData('updateForwarder', [forwarder.address, false]);
      await execViaTimelock(off, ethers.id('remove-forwarder'));
      expect(await gov.isTrustedForwarder(forwarder.address)).to.equal(false);
    });
  });

  describe('UUPS upgrade (_authorizeUpgrade / onlyGovernance)', function () {
    it('rejects a direct upgradeToAndCall from an external caller', async function () {
      const newImpl = await ethers.deployContract('MetaGovernor');
      await newImpl.waitForDeployment();
      await expect(
        gov.connect(outsider).upgradeToAndCall(await newImpl.getAddress(), '0x'),
      ).to.be.revertedWith('Governor: onlyExecutor');
    });

    it('upgrades when routed through the timelock executor', async function () {
      const newImpl = await ethers.deployContract('MetaGovernor');
      await newImpl.waitForDeployment();
      const newImplAddr = await newImpl.getAddress();

      const before = await upgrades.erc1967.getImplementationAddress(govAddr);
      expect(before.toLowerCase()).to.not.equal(newImplAddr.toLowerCase());

      const data = gov.interface.encodeFunctionData('upgradeToAndCall', [newImplAddr, '0x']);
      await execViaTimelock(data, ethers.id('upgrade-impl'));

      const after = await upgrades.erc1967.getImplementationAddress(govAddr);
      expect(after.toLowerCase()).to.equal(newImplAddr.toLowerCase());
    });
  });
});

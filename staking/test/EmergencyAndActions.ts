import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// Coverage for Staking:
//   * emergencyUnstakeERC20 — user-protection escape hatch that returns principal even while the
//     pool is paused (and normal unstake is blocked). Forfeits pending rewards by design.
//   * scheduleAction / executeAction — privileged scheduler restricted to ADMIN_ROLE.

// initialize(admin, rewardToken, duration, cooldownSecs, depositFeeBps, feeTreasury, arrowlist, forwarders)
async function deployStaking() {
  const [admin, alice] = await ethers.getSigners();
  const reward = await ethers.deployContract('MockERC20', ['Reward', 'RWD']);
  const stake = await ethers.deployContract('MockERC20', ['Stake', 'STK']);
  const factory = await ethers.getContractFactory('Staking');
  const staking = await upgrades.deployProxy(
    factory,
    [admin.address, reward.target, 1000, 0, 0, admin.address, [], []],
    {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor', 'incorrect-initializer-order'],
    },
  );
  await staking.waitForDeployment();
  return { admin, alice, reward, stake, staking };
}

describe('Staking emergency unstake + action gating', function () {
  describe('initialize sets reward precision in proxy storage', function () {
    it('reports rewardPrecision == 18 after a fresh proxy deployment', async function () {
      // Regression: an inline field initializer would leave this 0 in the proxy and break
      // _round()'s 10 ** (18 - rewardPrecision) factor. It must be assigned in initialize().
      const { staking } = await deployStaking();
      expect(await staking.rewardPrecision()).to.equal(18n);
    });
  });

  describe('emergencyUnstakeERC20 (escape hatch, works while paused)', function () {
    it('returns staked principal during a pause even though normal unstake is blocked', async function () {
      const { alice, stake, staking } = await deployStaking();
      await staking.setArrowlist(stake.target, true);

      await stake.mint(alice.address, 100n);
      await stake.connect(alice).approve(staking.target, 100n);
      await staking.connect(alice).stakeERC20(stake.target, 100n);
      expect(await stake.balanceOf(staking.target)).to.equal(100n);

      await staking.pause();
      // Normal unstake is gated by whenNotPaused...
      await expect(staking.connect(alice).unstakeERC20(stake.target, 100n)).to.be.reverted;
      // ...but the emergency escape hatch still lets the user recover their principal.
      await staking.connect(alice).emergencyUnstakeERC20(stake.target);

      expect(await stake.balanceOf(alice.address)).to.equal(100n);
      expect(await stake.balanceOf(staking.target)).to.equal(0n);
    });

    it('reverts when the caller has no position', async function () {
      const { alice, stake, staking } = await deployStaking();
      await staking.setArrowlist(stake.target, true);
      await expect(
        staking.connect(alice).emergencyUnstakeERC20(stake.target),
      ).to.be.revertedWith('none');
    });
  });

  describe('scheduleAction / executeAction are ADMIN_ROLE-gated', function () {
    it('rejects scheduleAction from a non-admin', async function () {
      const { alice, stake, staking } = await deployStaking();
      await expect(
        staking.connect(alice).scheduleAction(stake.target, 0, '0x12345678', 0, false, 0),
      ).to.be.reverted;
    });

    it('rejects executeAction from a non-admin but allows the admin', async function () {
      const { alice, stake, staking } = await deployStaking();
      await staking.setArrowlist(stake.target, true);
      await staking.scheduleAction(stake.target, 0, '0x12345678', 0, false, 0); // id 0, admin only

      await expect(staking.connect(alice).executeAction(0)).to.be.reverted;
      await expect(staking.executeAction(0)).to.emit(staking, 'ActionExecuted');
    });
  });
});

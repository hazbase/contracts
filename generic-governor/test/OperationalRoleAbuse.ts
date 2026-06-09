import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine } from '@nomicfoundation/hardhat-network-helpers';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployGovernorFixture() {
  const [admin, proposer, voter, rogue] = await ethers.getSigners();
  const token = await ethers.deployContract('MockVotesToken');
  const strategy = await ethers.deployContract('OneTokenOneVote', [4, 10n]);
  const timelock = await ethers.deployContract('TimelockControllerUpgradeable');
  await timelock.initialize(0, [], [], admin.address);

  await token.mint(proposer.address, 100n);
  await token.mint(voter.address, 50n);
  await token.connect(proposer).delegate(proposer.address);
  await token.connect(voter).delegate(voter.address);
  await mine(1);

  const governorFactory = await ethers.getContractFactory('GenericGovernor');
  const governor = await upgrades.deployProxy(
    governorFactory,
    [admin.address, 'Role Abuse Governor', token.target, timelock.target, strategy.target, []],
    {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    },
  );
  await governor.waitForDeployment();

  return { admin, rogue, governor, strategy };
}

describe('GenericGovernor operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-01 governance config setter abuse rejection', async function () {
    const { rogue, governor, strategy } = await deployGovernorFixture();

    await expect(governor.connect(rogue).updateForwarder(rogue.address, true)).to.be.reverted;
    await expect(governor.connect(rogue).updateStrategy(await strategy.id(), await strategy.getAddress())).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-01',
      source: 'generic-governor',
      checks: {
        governance_config_updates_blocked: true,
      },
    });
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitOpsLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_OPS_LEDGER_OUTPUT === '1') {
    console.log(`RWA_OPS_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployGovernorFixture() {
  const [admin, proposer, voter] = await ethers.getSigners();
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
    [admin.address, 'Operational Recovery Governor', token.target, timelock.target, strategy.target, []],
    {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    },
  );
  await governor.waitForDeployment();

  await timelock.grantRole(await timelock.PROPOSER_ROLE(), governor.target);
  await timelock.grantRole(await timelock.EXECUTOR_ROLE(), ethers.ZeroAddress);

  return { proposer, voter, governor };
}

describe('GenericGovernor operational recovery coverage', function () {
  it('emits ops ledger for OPS-REC-04 governance-approved workout state', async function () {
    const { proposer, voter, governor } = await deployGovernorFixture();
    const target = await ethers.deployContract('MockGovernorTarget');
    const targets = [target.target];
    const values = [0n];
    const calldatas = [target.interface.encodeFunctionData('setValue', [730n])];
    const description = 'Workout approval after issuer incident';
    const latest = await ethers.provider.getBlock('latest');
    const startTs = BigInt(latest!.timestamp) + 5n;
    const endTs = startTs + 3600n;

    const proposalId = await governor.connect(proposer).propose.staticCall(proposer.address, targets, values, calldatas, description, startTs, endTs);
    await governor.connect(proposer).propose(proposer.address, targets, values, calldatas, description, startTs, endTs);
    await time.increaseTo(Number(startTs + 1n));
    await governor.connect(proposer).castVote(proposalId, 1);
    await governor.connect(voter).castVote(proposalId, 1);
    await time.increaseTo(Number(endTs + 1n));

    const descriptionHash = ethers.keccak256(ethers.toUtf8Bytes(description));
    await governor.queue(targets, values, calldatas, descriptionHash);
    await governor.execute(targets, values, calldatas, descriptionHash);
    expect(await target.value()).to.equal(730n);

    emitOpsLedger({
      scenario: 'OPS-REC-04',
      source: 'generic-governor',
      ledger: {
        governance_override_state: 'workout-approved',
      },
      checks: {
        governance_workout_approved: true,
      },
    });
  });
});

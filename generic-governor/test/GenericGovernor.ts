import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitGovernanceLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_GOV_LEDGER_OUTPUT === '1') {
    console.log(`RWA_GOV_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('GenericGovernor internal coverage', function () {
  it('proposes, queues, and executes a timelocked action', async function () {
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
      [admin.address, 'Generic Governor', token.target, timelock.target, strategy.target, []],
      {
        kind: 'uups',
        initializer: 'initialize',
        unsafeAllow: ['constructor'],
      }
    );
    await governor.waitForDeployment();

    await timelock.grantRole(await timelock.PROPOSER_ROLE(), governor.target);
    await timelock.grantRole(await timelock.EXECUTOR_ROLE(), ethers.ZeroAddress);

    const target = await ethers.deployContract('MockGovernorTarget');
    const targets = [target.target];
    const values = [0n];
    const calldatas = [target.interface.encodeFunctionData('setValue', [42n])];
    const description = 'Internal governance execution';
    const latest = await ethers.provider.getBlock('latest');
    const startTs = BigInt(latest!.timestamp) + 5n;
    const endTs = startTs + 3600n;

    const proposalId = await governor.connect(proposer).propose.staticCall(
      proposer.address,
      targets,
      values,
      calldatas,
      description,
      startTs,
      endTs
    );

    await governor
      .connect(proposer)
      .propose(proposer.address, targets, values, calldatas, description, startTs, endTs);

    expect(await governor.state(proposalId)).to.equal(0n);

    await time.increaseTo(Number(startTs + 1n));
    expect(await governor.state(proposalId)).to.equal(1n);

    await governor.connect(proposer).castVote(proposalId, 1);
    await governor.connect(voter).castVote(proposalId, 1);

    await time.increaseTo(Number(endTs + 1n));
    expect(await governor.state(proposalId)).to.equal(4n);

    const descriptionHash = ethers.keccak256(ethers.toUtf8Bytes(description));
    await governor.queue(targets, values, calldatas, descriptionHash);
    expect(await governor.state(proposalId)).to.equal(5n);

    await governor.execute(targets, values, calldatas, descriptionHash);
    expect(await target.value()).to.equal(42n);
    expect(await governor.state(proposalId)).to.equal(7n);

    emitGovernanceLedger({
      scenario: 'GOV-CS-02',
      source: 'generic-governor',
      ledger: {
        proposal_state: 'executed',
        target_value: '42',
        votes_for: '150',
        votes_against: '0',
        timelock_delay: '0',
      },
      checks: {
        proposal_created: true,
        votes_cast: true,
        queued: true,
        executed: true,
      },
    });
  });
});

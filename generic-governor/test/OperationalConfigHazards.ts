import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine, time } from '@nomicfoundation/hardhat-network-helpers';

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('GenericGovernor configuration-hazard coverage', function () {
  it('emits config ledger for CFG-04 timelock topology drift that safe-fails queueing', async function () {
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
      [admin.address, 'Config Drift Governor', token.target, timelock.target, strategy.target, []],
      {
        kind: 'uups',
        initializer: 'initialize',
        unsafeAllow: ['constructor'],
      },
    );
    await governor.waitForDeployment();

    const target = await ethers.deployContract('MockGovernorTarget');
    const targets = [target.target];
    const values = [0n];
    const calldatas = [target.interface.encodeFunctionData('setValue', [77n])];
    const description = 'Timelock topology drift queue failure';
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
      endTs,
    );
    await governor.connect(proposer).propose(proposer.address, targets, values, calldatas, description, startTs, endTs);
    await time.increaseTo(Number(startTs + 1n));
    await governor.connect(proposer).castVote(proposalId, 1);
    await governor.connect(voter).castVote(proposalId, 1);
    await time.increaseTo(Number(endTs + 1n));

    const descriptionHash = ethers.keccak256(ethers.toUtf8Bytes(description));
    await expect(governor.queue(targets, values, calldatas, descriptionHash)).to.be.reverted;
    expect(await target.value()).to.equal(0n);

    emitConfigLedger({
      scenario: 'CFG-04',
      source: 'generic-governor',
      ledger: {
        governance_config_state: 'queue_blocked_without_timelock_proposer',
      },
      checks: {
        governance_safe_fail_observed: true,
        governance_bypass_absent: true,
      },
    });
  });
});

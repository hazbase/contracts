import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine } from '@nomicfoundation/hardhat-network-helpers';

// Coverage:
//   GenericGovernor.propose — the `proposer` argument may not be spoofed: the caller must
//        either BE that proposer or hold META_ROLE (the meta-tx relayer path).
//   OnePersonOneVote.quorum — quorum is an ABSOLUTE number of distinct yes-voters (holder-vote
//        units matching weight()'s {0,1}), not a percentage of raw token supply.

async function deployGovernor() {
  const [admin, proposer, voter, relayer] = await ethers.getSigners();
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
    { kind: 'uups', initializer: 'initialize', unsafeAllow: ['constructor'] },
  );
  await governor.waitForDeployment();
  return { admin, proposer, voter, relayer, token, governor };
}

async function proposalArgs() {
  const target = await ethers.deployContract('MockGovernorTarget');
  const targets = [target.target];
  const values = [0n];
  const calldatas = [target.interface.encodeFunctionData('setValue', [42n])];
  const description = 'auth coverage';
  const latest = await ethers.provider.getBlock('latest');
  const startTs = BigInt(latest!.timestamp) + 5n;
  const endTs = startTs + 3600n;
  return { targets, values, calldatas, description, startTs, endTs };
}

describe('GenericGovernor proposer authorization', function () {
  it('rejects a caller proposing on behalf of someone else without META_ROLE', async function () {
    const { proposer, voter, governor } = await deployGovernor();
    const { targets, values, calldatas, description, startTs, endTs } = await proposalArgs();

    // `voter` tries to submit a proposal attributed to `proposer` — spoofing the proposer field.
    await expect(
      governor
        .connect(voter)
        .propose(proposer.address, targets, values, calldatas, description, startTs, endTs),
    ).to.be.revertedWith('proposer-not-authorized');
  });

  it('allows the proposer to propose for themselves', async function () {
    const { proposer, governor } = await deployGovernor();
    const { targets, values, calldatas, description, startTs, endTs } = await proposalArgs();

    await expect(
      governor
        .connect(proposer)
        .propose(proposer.address, targets, values, calldatas, description, startTs, endTs),
    ).to.not.be.reverted;
  });

  it('allows a META_ROLE relayer to propose on behalf of a proposer', async function () {
    const { admin, proposer, relayer, governor } = await deployGovernor();
    const { targets, values, calldatas, description, startTs, endTs } = await proposalArgs();

    await governor.connect(admin).grantRole(await governor.META_ROLE(), relayer.address);

    await expect(
      governor
        .connect(relayer)
        .propose(proposer.address, targets, values, calldatas, description, startTs, endTs),
    ).to.not.be.reverted;
  });
});

describe('OnePersonOneVote strategy quorum units', function () {
  it('returns an absolute quorum independent of total supply', async function () {
    const strat = await ethers.deployContract('OnePersonOneVote', [3n, 2n]);
    // Same absolute quorum regardless of the (token-supply) argument — proves it is NOT a percentage.
    expect(await strat.quorum(0n, 0n)).to.equal(3n);
    expect(await strat.quorum(1_000_000n, 12345n)).to.equal(3n);
    expect(await strat.quorumVotes()).to.equal(3n);
  });

  it('exposes the proposer threshold in holder-vote units and the OPOV id', async function () {
    const strat = await ethers.deployContract('OnePersonOneVote', [3n, 2n]);
    expect(await strat.minThreshold()).to.equal(2n);
    expect(await strat.id()).to.equal('0x4f504f56'); // "OPOV"
  });

  it('rejects a zero quorum at construction', async function () {
    await expect(ethers.deployContract('OnePersonOneVote', [0n, 2n])).to.be.revertedWith('quorum0');
  });
});

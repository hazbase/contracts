import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitGovernanceLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_GOV_LEDGER_OUTPUT === '1') {
    console.log(`RWA_GOV_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('MetaGovernor internal coverage', function () {
  async function deployMetaFixture() {
    const [admin, proposer] = await ethers.getSigners();
    const econ = await ethers.deployContract('MockGovernorBasic', [admin.address]);
    const soc = await ethers.deployContract('MockGovernorBasic', [admin.address]);
    const timelock = await ethers.deployContract('TimelockControllerUpgradeable');
    await timelock.initialize(0, [], [], admin.address);

    const metaFactory = await ethers.getContractFactory('MetaGovernor');
    const meta = await upgrades.deployProxy(
      metaFactory,
      [admin.address, 'Meta Governor', econ.target, soc.target, timelock.target, []],
      {
        kind: 'uups',
        initializer: 'initialize',
      }
    );
    await meta.waitForDeployment();

    const metaRole = await econ.META_ROLE();
    await econ.grantRole(metaRole, meta.target);
    await soc.grantRole(metaRole, meta.target);
    await timelock.grantRole(await timelock.PROPOSER_ROLE(), meta.target);
    await timelock.grantRole(await timelock.EXECUTOR_ROLE(), ethers.ZeroAddress);

    const target = await ethers.deployContract('MockMetaTarget');
    const targets = [target.target];
    const values = [0n];
    const calldatas = [target.interface.encodeFunctionData('setValue', [777n])];
    const description = 'Meta governance execution';
    const latest = await ethers.provider.getBlock('latest');
    const startTs = BigInt(latest!.timestamp) + 10n;
    const endTs = startTs + 3600n;

    const proposalId = await meta.propose.staticCall(2, targets, values, calldatas, description, startTs, endTs);
    await meta.connect(proposer).propose(2, targets, values, calldatas, description, startTs, endTs);

    return { admin, proposer, econ, soc, timelock, meta, target, targets, values, calldatas, description, proposalId };
  }

  it('finalizes after both child governors pass and executes through timelock', async function () {
    const { admin, econ, soc, timelock, meta, target, targets, values, calldatas, proposalId } = await deployMetaFixture();

    await econ.connect(admin).setTally(proposalId, 800n, 200n, 1_000n);
    await soc.connect(admin).setTally(proposalId, 700n, 300n, 1_000n);
    await econ.connect(admin).setState(proposalId, 4);
    await soc.connect(admin).setState(proposalId, 4);

    await expect(meta.finalize(proposalId)).to.emit(meta, 'Finalized');

    const salt = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [proposalId]));
    await timelock.executeBatch(targets, values, calldatas, ethers.ZeroHash, salt);

    expect(await target.value()).to.equal(777n);

    emitGovernanceLedger({
      scenario: 'GOV-CS-03',
      source: 'meta-governor',
      ledger: {
        econ_tally: { yes: '800', no: '200', supply: '1000' },
        soc_tally: { yes: '700', no: '300', supply: '1000' },
        finalized: true,
        target_value: '777',
      },
      checks: {
        both_children_passed: true,
        finalized: true,
        timelock_executed: true,
      },
    });
  });

  it('rejects finalization when one child has not succeeded', async function () {
    const { admin, econ, soc, meta, proposalId } = await deployMetaFixture();

    await econ.connect(admin).setTally(proposalId, 800n, 200n, 1_000n);
    await soc.connect(admin).setTally(proposalId, 700n, 300n, 1_000n);
    await econ.connect(admin).setState(proposalId, 4);
    await soc.connect(admin).setState(proposalId, 1);

    await expect(meta.finalize(proposalId)).to.be.revertedWith('soc not passed');
  });
});

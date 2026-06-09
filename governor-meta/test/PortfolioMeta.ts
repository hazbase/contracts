import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitEquityLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_EQUITY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_EQUITY_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployMetaFixture() {
  const [admin, proposer] = await ethers.getSigners();
  const econ = await ethers.deployContract('MockGovernorBasic', [admin.address]);
  const soc = await ethers.deployContract('MockGovernorBasic', [admin.address]);
  const timelock = await ethers.deployContract('TimelockControllerUpgradeable');
  await timelock.initialize(0, [], [], admin.address);

  const metaFactory = await ethers.getContractFactory('MetaGovernor');
  const meta = await upgrades.deployProxy(
    metaFactory,
    [admin.address, 'Equity Meta Governor', econ.target, soc.target, timelock.target, []],
    {
      kind: 'uups',
      initializer: 'initialize',
    },
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
  const calldatas = [target.interface.encodeFunctionData('setValue', [200n])];
  const description = 'Meta approval for reverse split';
  const latest = await ethers.provider.getBlock('latest');
  const startTs = BigInt(latest!.timestamp) + 10n;
  const endTs = startTs + 3600n;

  const proposalId = await meta.propose.staticCall(2, targets, values, calldatas, description, startTs, endTs);
  await meta.connect(proposer).propose(2, targets, values, calldatas, description, startTs, endTs);

  return { admin, econ, soc, timelock, meta, target, targets, values, calldatas, proposalId };
}

describe('MetaGovernor common-stock coverage', function () {
  it('emits equity ledger for EQTY-CS-05 dual-governor approval on structural action', async function () {
    const { admin, econ, soc, timelock, meta, target, targets, values, calldatas, proposalId } = await deployMetaFixture();

    await econ.connect(admin).setTally(proposalId, 900n, 100n, 1_000n);
    await soc.connect(admin).setTally(proposalId, 850n, 150n, 1_000n);
    await econ.connect(admin).setState(proposalId, 4);
    await soc.connect(admin).setState(proposalId, 4);

    await expect(meta.finalize(proposalId)).to.emit(meta, 'Finalized');

    const salt = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(['uint256'], [proposalId]));
    await timelock.executeBatch(targets, values, calldatas, ethers.ZeroHash, salt);
    expect(await target.value()).to.equal(200n);

    emitEquityLedger({
      scenario: 'EQTY-CS-05',
      source: 'meta-governor',
      ledger: {
        proposal_state: 'meta-executed',
        split_state: 'dual-approval-complete',
      },
      checks: {
        dual_governor_approval_complete: true,
      },
    });
  });
});

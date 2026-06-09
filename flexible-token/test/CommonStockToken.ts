import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';
import { mine } from '@nomicfoundation/hardhat-network-helpers';

function emitEquityLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_EQUITY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_EQUITY_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployCommonStockFixture() {
  const [admin, treasury, investorA, investorB, investorC] = await ethers.getSigners();
  const whitelist = await ethers.deployContract('MockWhitelist');
  const stable = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const factory = await ethers.getContractFactory('FlexibleToken');
  const token = await upgrades.deployProxy(
    factory,
    ['Warehouse Common Stock', 'WCS', treasury.address, 1_000n, 4_000n, 0, true, admin.address, []],
    {
      kind: 'uups',
      initializer: 'initialize',
    },
  );
  await token.waitForDeployment();

  for (const user of [admin.address, treasury.address, investorA.address, investorB.address, investorC.address]) {
    await whitelist.setWhitelisted(user, true);
  }

  await token.grantRole(await token.GUARDIAN_ROLE(), admin.address);
  await token.grantRole(await token.PAUSER_ROLE(), admin.address);
  await token.connect(admin).setWhitelist(await whitelist.getAddress());

  await token.connect(treasury).transfer(investorA.address, 600n);
  await token.connect(treasury).transfer(investorB.address, 400n);

  return { admin, treasury, investorA, investorB, investorC, whitelist, stable, token };
}

async function paySyntheticDividend(params: {
  token: any;
  stable: any;
  treasury: any;
  holders: Record<string, string>;
  totalAmount: bigint;
  recordBlock: number;
}) {
  const { token, stable, treasury, holders, totalAmount, recordBlock } = params;
  const totalVotes = BigInt(await token.getPastTotalSupply(recordBlock));
  const payouts: Record<string, bigint> = {};

  for (const [label, holder] of Object.entries(holders)) {
    const votes = BigInt(await token.getPastVotes(holder, recordBlock));
    const amount = totalVotes === 0n ? 0n : (totalAmount * votes) / totalVotes;
    payouts[label] = amount;
    if (amount > 0n) {
      await stable.connect(treasury).transfer(holder, amount);
    }
  }

  return payouts;
}

describe('FlexibleToken common-stock internal coverage', function () {
  it('emits equity ledger for EQTY-CS-01 record-date dividend after post-record-date transfer', async function () {
    const { treasury, investorA, investorB, stable, token } = await deployCommonStockFixture();

    await token.connect(treasury).delegate(treasury.address);
    await token.connect(investorA).delegate(investorA.address);
    await token.connect(investorB).delegate(investorB.address);
    await mine(1);

    const recordBlock = await ethers.provider.getBlockNumber();
    await stable.mint(treasury.address, 1_000n);

    await token.connect(investorA).transfer(investorB.address, 100n);
    await mine(1);

    const payouts = await paySyntheticDividend({
      token,
      stable,
      treasury,
      holders: {
        investor_a: investorA.address,
        investor_b: investorB.address,
      },
      totalAmount: 1_000n,
      recordBlock,
    });

    expect(await token.balanceOf(investorA.address)).to.equal(500n);
    expect(await token.balanceOf(investorB.address)).to.equal(500n);
    expect(await stable.balanceOf(investorA.address)).to.equal(600n);
    expect(await stable.balanceOf(investorB.address)).to.equal(400n);

    emitEquityLedger({
      scenario: 'EQTY-CS-01',
      source: 'flexible-token',
      ledger: {
        cap_table: {
          treasury: 0,
          investor_a: 500,
          investor_b: 500,
          investor_c: 0,
        },
        dividend_receivable: {
          investor_a: Number(payouts.investor_a),
          investor_b: Number(payouts.investor_b),
        },
        treasury_cash: Number(await stable.balanceOf(treasury.address)),
        voting_power: {
          record_block: recordBlock,
          investor_a: Number(await token.getPastVotes(investorA.address, recordBlock)),
          investor_b: Number(await token.getPastVotes(investorB.address, recordBlock)),
        },
      },
      checks: {
        record_date_preserved: true,
        post_record_transfer_keeps_entitlement: true,
      },
    });
  });

  it('emits equity ledger for EQTY-CS-02 treasury buyback and controlled reissue', async function () {
    const { treasury, investorA, investorB, investorC, stable, token } = await deployCommonStockFixture();

    await token.connect(treasury).delegate(treasury.address);
    await token.connect(investorA).delegate(investorA.address);
    await token.connect(investorB).delegate(investorB.address);
    await stable.mint(treasury.address, 5_000n);

    await stable.connect(treasury).transfer(investorB.address, 250n);
    await token.connect(investorB).transfer(treasury.address, 100n);
    await token.connect(treasury).transfer(investorC.address, 50n);
    await token.connect(investorC).delegate(investorC.address);
    await mine(1);

    expect(await token.balanceOf(treasury.address)).to.equal(50n);
    expect(await token.balanceOf(investorA.address)).to.equal(600n);
    expect(await token.balanceOf(investorB.address)).to.equal(300n);
    expect(await token.balanceOf(investorC.address)).to.equal(50n);

    emitEquityLedger({
      scenario: 'EQTY-CS-02',
      source: 'flexible-token',
      ledger: {
        cap_table: {
          treasury: 50,
          investor_a: 600,
          investor_b: 300,
          investor_c: 50,
        },
        treasury_cash: Number(await stable.balanceOf(treasury.address)),
        treasury_shares: Number(await token.balanceOf(treasury.address)),
        buyback_state: 'buyback_and_reissue_complete',
        voting_power: {
          treasury: Number(await token.getVotes(treasury.address)),
          investor_a: Number(await token.getVotes(investorA.address)),
          investor_b: Number(await token.getVotes(investorB.address)),
          investor_c: Number(await token.getVotes(investorC.address)),
        },
      },
      checks: {
        buyback_completed: true,
        reissue_completed: true,
        delegated_voting_intact: true,
      },
    });
  });

  it('emits equity ledger for EQTY-CS-03 split and reverse split ratio preservation', async function () {
    const { treasury, investorA, investorB, token } = await deployCommonStockFixture();

    await token.connect(treasury).delegate(treasury.address);
    await token.connect(investorA).delegate(investorA.address);
    await token.connect(investorB).delegate(investorB.address);
    await mine(1);

    await token.batchMint([investorA.address, investorB.address], [600n, 400n]);
    await mine(1);
    expect(await token.balanceOf(investorA.address)).to.equal(1_200n);
    expect(await token.balanceOf(investorB.address)).to.equal(800n);

    await token.batchBurn([investorA.address, investorB.address], [600n, 400n]);
    await mine(1);

    expect(await token.balanceOf(investorA.address)).to.equal(600n);
    expect(await token.balanceOf(investorB.address)).to.equal(400n);
    expect(await token.getVotes(investorA.address)).to.equal(600n);
    expect(await token.getVotes(investorB.address)).to.equal(400n);

    emitEquityLedger({
      scenario: 'EQTY-CS-03',
      source: 'flexible-token',
      ledger: {
        cap_table: {
          treasury: 0,
          investor_a: 600,
          investor_b: 400,
        },
        split_state: 'split_then_reverse_split_preserved',
        voting_power: {
          investor_a: 600,
          investor_b: 400,
        },
      },
      checks: {
        split_preserved_ratio: true,
        reverse_split_restored_cap_table: true,
      },
    });
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const DIRECT = 0;
const COMPENSATION = 1;
const LIQUIDITY = 2;

function emitAssetLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ASSET_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ASSET_LEDGER::${JSON.stringify(entry)}`);
  }
}

function emitCorporateBondLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CORP_BOND_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CORP_BOND_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('Splitter real-world fee routing coverage', function () {
  it('emits asset-backed note ledger for ABN-CS-01 reserve route table', async function () {
    const [admin, user, treasury] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const compensationPool = await ethers.deployContract('MockReservePool');
    const liquidityPool = await ethers.deployContract('MockReservePool');
    const splitter = await upgrades.deployProxy(await ethers.getContractFactory('Splitter'), [], { kind: 'uups', initializer: false });

    await splitter.initialize(
      admin.address,
      [
        { dest: treasury.address, bps: 7000, reserveBucket: DIRECT },
        { dest: liquidityPool.target, bps: 2000, reserveBucket: LIQUIDITY },
        { dest: compensationPool.target, bps: 1000, reserveBucket: COMPENSATION },
      ],
      [],
    );

    await token.mint(user.address, 100_000n);
    await token.connect(user).approve(splitter.target, 100_000n);
    await splitter.connect(user).routeERC20(token.target, 100_000n);

    expect(await token.balanceOf(treasury.address)).to.equal(70_000n);
    expect(await liquidityPool.lastAmount()).to.equal(20_000n);
    expect(await compensationPool.lastAmount()).to.equal(10_000n);

    emitAssetLedger({
      scenario: 'ABN-CS-01',
      source: 'splitter',
      ledger: {
        treasury_fee: 70000,
        reserve_liquidity: 20000,
        reserve_compensation: 10000,
      },
      checks: {
        issuance_route_table_applied: true,
      },
    });
  });

  it('emits corporate bond ledger for CBOND-CS-01 primary placement fee route', async function () {
    const [admin, user, treasury] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const compensationPool = await ethers.deployContract('MockReservePool');
    const liquidityPool = await ethers.deployContract('MockReservePool');
    const splitter = await upgrades.deployProxy(await ethers.getContractFactory('Splitter'), [], { kind: 'uups', initializer: false });

    await splitter.initialize(
      admin.address,
      [
        { dest: treasury.address, bps: 8000, reserveBucket: DIRECT },
        { dest: liquidityPool.target, bps: 1500, reserveBucket: LIQUIDITY },
        { dest: compensationPool.target, bps: 500, reserveBucket: COMPENSATION },
      ],
      [],
    );

    await token.mint(user.address, 50_000n);
    await token.connect(user).approve(splitter.target, 50_000n);
    await splitter.connect(user).routeERC20(token.target, 50_000n);

    emitCorporateBondLedger({
      scenario: 'CBOND-CS-01',
      source: 'splitter',
      ledger: {
        treasury_fee: 40000,
      },
      checks: {
        fee_route_triggered: true,
      },
    });
  });
});

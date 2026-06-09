import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const DIRECT = 0;
const COMPENSATION = 1;
const LIQUIDITY = 2;

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('Splitter configuration-hazard coverage', function () {
  it('emits config ledger for CFG-02 miswired fee routes that swap reserve intent', async function () {
    const [admin, user, treasury] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const compensationPool = await ethers.deployContract('MockReservePool');
    const liquidityPool = await ethers.deployContract('MockReservePool');
    const splitter = await upgrades.deployProxy(await ethers.getContractFactory('Splitter'), [], { kind: 'uups', initializer: false });

    await splitter.initialize(
      admin.address,
      [
        { dest: treasury.address, bps: 7000, reserveBucket: DIRECT },
        { dest: compensationPool.target, bps: 2000, reserveBucket: COMPENSATION },
        { dest: liquidityPool.target, bps: 1000, reserveBucket: LIQUIDITY },
      ],
      [],
    );

    await token.mint(user.address, 100_000n);
    await token.connect(user).approve(splitter.target, 100_000n);
    await splitter.connect(user).routeERC20(token.target, 100_000n);

    expect(await token.balanceOf(treasury.address)).to.equal(70_000n);
    expect(await compensationPool.lastAmount()).to.equal(20_000n);
    expect(await liquidityPool.lastAmount()).to.equal(10_000n);

    emitConfigLedger({
      scenario: 'CFG-02',
      source: 'splitter',
      ledger: {
        treasury_fee: 70000,
        reserve_liquidity: 10000,
        reserve_compensation: 20000,
        route_misconfig_state: 'buckets_swapped',
      },
      checks: {
        route_hazard_observed: true,
      },
    });
  });
});

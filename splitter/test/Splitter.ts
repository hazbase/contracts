import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const DIRECT = 0;
const COMPENSATION = 1;
const LIQUIDITY = 2;

function emitRwaLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_LEDGER_OUTPUT === '1') {
    console.log(`RWA_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('Splitter', function () {
  it('routes ERC20 funds into the requested ReservePool buckets', async function () {
    const [admin, user] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Mock Token', 'MOCK']);
    const compensationPool = await ethers.deployContract('MockReservePool');
    const liquidityPool = await ethers.deployContract('MockReservePool');
    const splitter = await upgrades.deployProxy(await ethers.getContractFactory('Splitter'), [], { kind: 'uups', initializer: false });

    await splitter.initialize(
      admin.address,
      [
        { dest: compensationPool.target, bps: 5000, reserveBucket: COMPENSATION },
        { dest: liquidityPool.target, bps: 5000, reserveBucket: LIQUIDITY },
      ],
      []
    );

    await token.mint(user.address, 1000n);
    await token.connect(user).approve(splitter.target, 1000n);
    await splitter.connect(user).routeERC20(token.target, 1000n);

    expect(await compensationPool.compensationCalls()).to.equal(1n);
    expect(await compensationPool.lastToken()).to.equal(token.target);
    expect(await compensationPool.lastAmount()).to.equal(500n);

    expect(await liquidityPool.liquidityCalls()).to.equal(1n);
    expect(await liquidityPool.lastToken()).to.equal(token.target);
    expect(await liquidityPool.lastAmount()).to.equal(500n);
  });

  it('keeps non-Reserve direct routes backward compatible', async function () {
    const [admin, user, treasury] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Mock Token', 'MOCK']);
    const splitter = await upgrades.deployProxy(await ethers.getContractFactory('Splitter'), [], { kind: 'uups', initializer: false });

    await splitter.initialize(
      admin.address,
      [{ dest: treasury.address, bps: 10000, reserveBucket: DIRECT }],
      []
    );

    await token.mint(user.address, 750n);
    await token.connect(user).approve(splitter.target, 750n);
    await splitter.connect(user).routeERC20(token.target, 750n);

    expect(await token.balanceOf(treasury.address)).to.equal(750n);
  });

  it('emits RWA ledger for CS-01 canonical fee split', async function () {
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
      []
    );

    await token.mint(user.address, 100_000n);
    await token.connect(user).approve(splitter.target, 100_000n);
    await splitter.connect(user).routeERC20(token.target, 100_000n);

    expect(await token.balanceOf(treasury.address)).to.equal(70_000n);
    expect(await liquidityPool.lastAmount()).to.equal(20_000n);
    expect(await compensationPool.lastAmount()).to.equal(10_000n);

    emitRwaLedger({
      scenario: 'CS-01',
      source: 'splitter',
      ledger: {
        treasury_fee: 70000,
        reserve_liquidity: 20000,
        reserve_compensation: 10000,
      },
    });
  });

  it('emits RWA ledger for CS-03 canonical secondary fee split', async function () {
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
      []
    );

    await token.mint(user.address, 20_000n);
    await token.connect(user).approve(splitter.target, 20_000n);
    await splitter.connect(user).routeERC20(token.target, 20_000n);

    expect(await token.balanceOf(treasury.address)).to.equal(14_000n);
    expect(await liquidityPool.lastAmount()).to.equal(4_000n);
    expect(await compensationPool.lastAmount()).to.equal(2_000n);

    emitRwaLedger({
      scenario: 'CS-03',
      source: 'splitter',
      ledger: {
        treasury_fee: 14000,
        reserve_liquidity: 4000,
        reserve_compensation: 2000,
      },
    });
  });
});

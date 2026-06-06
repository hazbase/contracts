import { expect } from "chai";
import { ethers } from "hardhat";

import { AMM, ERC20TokenHelper, Pool, Router } from "../../../@hazbase/amm/src";

const DEFAULTS = {
  baseFeeBps: 30,
  feeAlphaBps: 0,
  lvl1Bps: 5_000,
  lvl2Bps: 8_000,
  lvl3Bps: 9_900,
  maxTxBps: 5_000,
};

function expectPositive(value: bigint, label: string) {
  expect(value > 0n, label).to.equal(true);
}

async function wait(txPromise: Promise<{ wait(): Promise<unknown> }>) {
  await (await txPromise).wait();
}

async function futureDeadline(seconds = 3_600): Promise<bigint> {
  const block = await ethers.provider.getBlock("latest");
  if (!block) throw new Error("latest block not found");
  return BigInt(block.timestamp + seconds);
}

async function deployStack() {
  const [owner] = await ethers.getSigners();

  const MockERC20 = await ethers.getContractFactory("MockAmmERC20");
  const tokenA = await MockERC20.deploy("USD Coin", "USDC", 6);
  const tokenB = await MockERC20.deploy("JPY Coin", "JPYC", 6);
  await tokenA.waitForDeployment();
  await tokenB.waitForDeployment();

  const MockWNative = await ethers.getContractFactory("MockWNative");
  const wnative = await MockWNative.deploy();
  await wnative.waitForDeployment();

  const MockSplitter = await ethers.getContractFactory("MockAmmSplitter");
  const splitter = await MockSplitter.deploy();
  await splitter.waitForDeployment();

  const CircuitBreakerAMM = await ethers.getContractFactory("CircuitBreakerAMM");
  const implementation = await CircuitBreakerAMM.deploy();
  await implementation.waitForDeployment();

  const AMMFactory = await ethers.getContractFactory("AMMFactory");
  const factory = await AMMFactory.deploy(
    await implementation.getAddress(),
    await splitter.getAddress(),
    DEFAULTS,
    owner.address,
  );
  await factory.waitForDeployment();

  const AMMRouter = await ethers.getContractFactory("AMMRouter");
  const routerContract = await AMMRouter.deploy(await factory.getAddress(), await wnative.getAddress());
  await routerContract.waitForDeployment();

  await wait(tokenA.mint(owner.address, ethers.parseUnits("10000000", 6)));
  await wait(tokenB.mint(owner.address, ethers.parseUnits("1000000000", 6)));

  return {
    owner,
    tokenAContract: tokenA,
    tokenBContract: tokenB,
    wnative,
    splitter,
    amm: new AMM(owner, undefined, await factory.getAddress()),
    router: new Router(owner, undefined, await routerContract.getAddress()),
    tokenA: ERC20TokenHelper.attach(await tokenA.getAddress(), owner),
    tokenB: ERC20TokenHelper.attach(await tokenB.getAddress(), owner),
    wnativeToken: ERC20TokenHelper.attach(await wnative.getAddress(), owner),
  };
}

describe("@hazbase/amm SDK integration", function () {
  it("wraps factory, router, pool, fees, and LP unit helpers", async function () {
    const { owner, splitter, amm, router, tokenA, tokenB } = await deployStack();

    const created = await amm.createPool({ tokenA: tokenA.address, tokenB: tokenB.address });
    expect(created.pool).to.match(/^0x[0-9a-fA-F]{40}$/);

    const pool = await amm.pool(tokenA.address, tokenB.address);
    expect(pool.address).to.equal(created.pool);
    expect(await amm.getPool(tokenA.address, tokenB.address)).to.equal(created.pool);

    await tokenA.approve(router.address, ethers.MaxUint256);
    await tokenB.approve(router.address, ethers.MaxUint256);

    const added = await router.addLiquidity({
      pair: pool.address,
      tokenA: tokenA.address,
      tokenB: tokenB.address,
      amountADesired: await tokenA.parse("10000"),
      amountBDesired: await tokenB.parse("1500000"),
      amountAMin: 0n,
      amountBMin: 0n,
      to: owner.address,
      deadline: await futureDeadline(),
    });
    expectPositive(added.amountA, "amountA");
    expectPositive(added.amountB, "amountB");
    expectPositive(added.liquidity, "liquidity");

    const tokens = await pool.tokens();
    expect([tokenA.address, tokenB.address]).to.include(tokens.token0);
    expect([tokenA.address, tokenB.address]).to.include(tokens.token1);

    const reserves = await pool.getReserves();
    expectPositive(reserves.reserve0, "reserve0");
    expectPositive(reserves.reserve1, "reserve1");
    expect(await pool.currentRV()).to.equal(0);
    expect(await pool.balanceOf(owner.address).format()).to.be.a("string");

    await tokenA.transfer(pool.address, await tokenA.parse("100"));
    await tokenB.transfer(pool.address, await tokenB.parse("15000"));
    const directMint = await pool.mint(owner.address);
    expectPositive(directMint.liquidity, "direct mint liquidity");

    await pool.transfer(pool.address, directMint.liquidity);
    const directBurn = await pool.burn(owner.address);
    expectPositive(directBurn.amount0, "direct burn amount0");
    expectPositive(directBurn.amount1, "direct burn amount1");

    const zeroForOne = tokenB.address === tokens.token0;
    const amountIn = await tokenB.parse("150");
    const poolQuote = await pool.quoteOut({ amountIn, zeroForOne });
    expectPositive(poolQuote.amountOut, "pool quote amountOut");
    expect(poolQuote.feeBps).to.equal(DEFAULTS.baseFeeBps);

    const quoteIn = await pool.quoteIn({ amountOut: poolQuote.amountOut / 2n, zeroForOne });
    expectPositive(quoteIn.amountIn, "pool quote amountIn");
    expect(quoteIn.feeBps).to.equal(DEFAULTS.baseFeeBps);

    const routerQuote = await router.quoteExactTokensForTokens({
      amountIn,
      path: [tokenB.address, tokenA.address],
    });
    expect(routerQuote.amountOut).to.equal(poolQuote.amountOut);
    expectPositive(routerQuote.totalFeeAmount, "router quote fee");

    await wait(splitter.setRejectERC20(true));
    const swap = await router.swapExactTokensForTokens({
      amountIn,
      amountOutMin: 1n,
      path: [tokenB.address, tokenA.address],
      to: owner.address,
      deadline: await futureDeadline(),
    });
    expect(swap.amountOut).to.equal(routerQuote.amountOut);
    expectPositive(await pool.pendingFee(tokenB.address), "pending fee");

    await wait(splitter.setRejectERC20(false));
    await pool.flushFees(tokenB.address, 0n);
    expect(await pool.pendingFee(tokenB.address)).to.equal(0n);

    const lpBalance = await pool.balanceOf(owner.address).raw();
    const removeLiquidity = lpBalance / 10n;
    await pool.approve(router.address, ethers.MaxUint256);
    const removed = await router.removeLiquidity({
      pair: pool.address,
      liquidity: removeLiquidity,
      tokenA: tokenA.address,
      tokenB: tokenB.address,
      amountAMin: 0n,
      amountBMin: 0n,
      to: owner.address,
      deadline: await futureDeadline(),
    });
    expectPositive(removed.amountA, "removed amountA");
    expectPositive(removed.amountB, "removed amountB");

    await pool.updateParams({ ...DEFAULTS, baseFeeBps: 25 });
    await pool.pause();
    await pool.unpause();
    await pool.flushNative(0n);
  });

  it("wraps ETH liquidity and token-to-ETH swaps", async function () {
    const { owner, amm, router, tokenA, wnativeToken } = await deployStack();

    const created = await amm.createPool({ tokenA: tokenA.address, tokenB: wnativeToken.address });
    const pool = Pool.attach(created.pool, owner);

    await tokenA.approve(router.address, ethers.MaxUint256);

    const added = await router.addLiquidityETH({
      pair: pool.address,
      token: tokenA.address,
      amountTokenDesired: await tokenA.parse("1000"),
      amountTokenMin: 0n,
      amountETHMin: 0n,
      value: ethers.parseEther("10"),
      to: owner.address,
      deadline: await futureDeadline(),
    });
    expectPositive(added.amountToken, "eth add token amount");
    expectPositive(added.amountETH, "eth add native amount");
    expectPositive(added.liquidity, "eth add liquidity");

    const tokenToEth = await router.swapExactTokensForETH({
      amountIn: await tokenA.parse("1"),
      amountOutMin: 1n,
      path: [tokenA.address, wnativeToken.address],
      to: owner.address,
      deadline: await futureDeadline(),
    });
    expectPositive(tokenToEth.amountOut, "token to eth amountOut");

    let reverted = false;
    try {
      await router.swapExactETHForTokens({
        amountIn: ethers.parseEther("0.1"),
        amountOutMin: 1n,
        path: [wnativeToken.address, tokenA.address],
        value: ethers.parseEther("0.1"),
        to: owner.address,
        deadline: await futureDeadline(),
      });
    } catch {
      reverted = true;
    }
    expect(reverted, "current AMMRouter.swapExactETHForTokens requires WNATIVE transferFrom").to.equal(true);
  });
});

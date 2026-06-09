import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRwaLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_LEDGER_OUTPUT === '1') {
    console.log(`RWA_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('ReservePool', function () {
  it('rejects native funding for the liquidity bucket', async function () {
    const [admin] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);

    await expect(
      reservePool.fundLiquidity(ethers.ZeroAddress, 1n, { value: 1n })
    ).to.be.revertedWith('native liquidity disabled');
  });

  it('still accepts native funding for the compensation bucket', async function () {
    const [admin] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);

    await expect(
      reservePool.fundCompensation(ethers.ZeroAddress, 5n, { value: 5n })
    )
      .to.emit(reservePool, 'CompensationFunded')
      .withArgs(ethers.ZeroAddress, 5n);

    expect(await reservePool.compensationOf(ethers.ZeroAddress)).to.equal(5n);
  });

  it('emits RWA ledger for CS-04 reserve compensation drill', async function () {
    const [admin, investor] = await ethers.getSigners();
    const reservePool = await upgrades.deployProxy(await ethers.getContractFactory('ReservePool'), [admin.address, admin.address, admin.address, []], { kind: 'uups' });
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);

    await reservePool.waitForDeployment();
    await reservePool.grantRole(await reservePool.ROYALTY_ROLE(), admin.address);
    await reservePool.grantRole(await reservePool.GUARDIAN_ROLE(), admin.address);

    await token.mint(admin.address, 1_000n);
    await token.approve(reservePool.target, 1_000n);

    await reservePool.fundLiquidity(token.target, 600n);
    await reservePool.fundCompensation(token.target, 400n);
    await reservePool.sweep(token.target, 150n, true);

    await expect(
      reservePool.payCompensation(token.target, investor.address, 200n)
    ).to.emit(reservePool, 'CompensationPaid').withArgs(token.target, investor.address, 200n);

    expect(await reservePool.liquidityOf(token.target)).to.equal(450n);
    expect(await reservePool.compensationOf(token.target)).to.equal(350n);
    expect(await token.balanceOf(investor.address)).to.equal(200n);

    emitRwaLedger({
      scenario: 'CS-04',
      source: 'reserve-pool',
      ledger: {
        reserve_liquidity: 450,
        reserve_compensation: 350,
      },
      checks: {
        compensation_paid: 200,
      },
    });
  });
});

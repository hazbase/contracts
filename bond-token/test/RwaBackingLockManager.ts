import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

async function deployBondFixture() {
  const [admin, backingOwner, other] = await ethers.getSigners();

  const bondFactory = await ethers.getContractFactory('BondToken');
  const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor'],
  });
  await bond.waitForDeployment();

  await bond.createClass(1n, [{ key: 'name', value: 'Liquid Backed RWA' }]);
  await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2032-01-01' }]);
  await bond.issue(backingOwner.address, 1n, 1n, 100n);

  const manager = await ethers.deployContract('RwaBackingLockManager', [admin.address]);
  await manager.waitForDeployment();
  await bond.connect(backingOwner).setApprovalForAll(await manager.getAddress(), true);

  return { admin, backingOwner, other, bond, manager };
}

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

describe('RwaBackingLockManager', function () {
  it('locks exact BondToken backing into custody for an order', async function () {
    const { backingOwner, bond, manager } = await deployBondFixture();
    const orderId = id('order-1');
    const liquidAssetId = id('liquid-rwa-asset');
    const termsHash = id('terms-1');
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 1800);

    await expect(
      manager.lock(
        orderId,
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        40n,
        liquidAssetId,
        termsHash,
        expiresAt,
      ),
    )
      .to.emit(manager, 'BackingLocked')
      .withArgs(
        orderId,
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        40n,
        liquidAssetId,
        termsHash,
        expiresAt,
      );

    expect(await bond.balanceOf(backingOwner.address, 1n, 1n)).to.equal(60n);
    expect(await bond.balanceOf(await manager.getAddress(), 1n, 1n)).to.equal(40n);

    const entry = await manager.getLock(orderId);
    expect(entry.status).to.equal(1);
    expect(entry.token).to.equal(await bond.getAddress());
    expect(entry.backingOwner).to.equal(backingOwner.address);
    expect(entry.classId).to.equal(1n);
    expect(entry.nonceId).to.equal(1n);
    expect(entry.amount).to.equal(40n);
    expect(entry.liquidAssetId).to.equal(liquidAssetId);
    expect(entry.termsHash).to.equal(termsHash);

    const totals = await manager.backingBalance(await bond.getAddress(), 1n, 1n);
    expect(totals.locked).to.equal(40n);
    expect(totals.consumed).to.equal(0n);
  });

  it('rejects duplicate order ids', async function () {
    const { backingOwner, bond, manager } = await deployBondFixture();
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 1800);

    await manager.lock(
      id('order-duplicate'),
      await bond.getAddress(),
      backingOwner.address,
      1n,
      1n,
      10n,
      id('liquid-rwa-asset'),
      id('terms-duplicate'),
      expiresAt,
    );

    await expect(
      manager.lock(
        id('order-duplicate'),
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-duplicate-2'),
        expiresAt,
      ),
    ).to.be.revertedWith('LOCK_EXISTS');
  });

  it('releases unconsumed backing before Liquid delivery', async function () {
    const { backingOwner, bond, manager } = await deployBondFixture();
    const orderId = id('order-release');
    const reasonCode = id('payment-expired');
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 1800);

    await manager.lock(
      orderId,
      await bond.getAddress(),
      backingOwner.address,
      1n,
      1n,
      25n,
      id('liquid-rwa-asset'),
      id('terms-release'),
      expiresAt,
    );

    await expect(manager.release(orderId, reasonCode))
      .to.emit(manager, 'BackingReleased')
      .withArgs(orderId, reasonCode);

    expect(await bond.balanceOf(backingOwner.address, 1n, 1n)).to.equal(100n);
    expect(await bond.balanceOf(await manager.getAddress(), 1n, 1n)).to.equal(0n);

    const entry = await manager.getLock(orderId);
    expect(entry.status).to.equal(2);

    const totals = await manager.backingBalance(await bond.getAddress(), 1n, 1n);
    expect(totals.locked).to.equal(0n);
    expect(totals.consumed).to.equal(0n);

    await expect(manager.consume(orderId, id('delivery-tx'))).to.be.revertedWith('LOCK_NOT_LOCKED');
  });

  it('consumes delivered backing without returning it to the issuer', async function () {
    const { backingOwner, bond, manager } = await deployBondFixture();
    const orderId = id('order-consume');
    const deliveryTxid = id('liquid-delivery-txid');
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 1800);

    await manager.lock(
      orderId,
      await bond.getAddress(),
      backingOwner.address,
      1n,
      1n,
      30n,
      id('liquid-rwa-asset'),
      id('terms-consume'),
      expiresAt,
    );

    await expect(manager.consume(orderId, deliveryTxid))
      .to.emit(manager, 'BackingConsumed')
      .withArgs(orderId, deliveryTxid);

    expect(await bond.balanceOf(backingOwner.address, 1n, 1n)).to.equal(70n);
    expect(await bond.balanceOf(await manager.getAddress(), 1n, 1n)).to.equal(30n);

    const entry = await manager.getLock(orderId);
    expect(entry.status).to.equal(3);
    expect(entry.liquidDeliveryTxid).to.equal(deliveryTxid);

    const totals = await manager.backingBalance(await bond.getAddress(), 1n, 1n);
    expect(totals.locked).to.equal(0n);
    expect(totals.consumed).to.equal(30n);

    await expect(manager.release(orderId, id('too-late'))).to.be.revertedWith('LOCK_NOT_LOCKED');
  });

  it('enforces roles and pause controls', async function () {
    const { backingOwner, other, bond, manager } = await deployBondFixture();
    const expiresAt = BigInt(Math.floor(Date.now() / 1000) + 1800);

    await expect(
      manager.connect(other).lock(
        id('order-unauthorized'),
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-unauthorized'),
        expiresAt,
      ),
    ).to.be.reverted;

    await manager.pause();
    await expect(
      manager.lock(
        id('order-paused'),
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-paused'),
        expiresAt,
      ),
    ).to.be.reverted;
  });
});

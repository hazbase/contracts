import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

describe('BondToken case-study coverage', function () {
  it('freezes each working snapshot once the next snapshot is created', async function () {
    const [admin, alice, bob] = await ethers.getSigners();
    const bondFactory = await ethers.getContractFactory('BondToken');
    const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await bond.waitForDeployment();

    await bond.createClass(1n, [{ key: 'name', value: 'Series A' }]);
    await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2030-01-01' }]);

    await bond.issue(alice.address, 1n, 1n, 100n);
    expect(await bond.balanceOfAt(alice.address, 1n, 1n, 1n)).to.equal(100n);
    expect(await bond.totalSupplyAt(1n, 1n, 1n)).to.equal(100n);

    await bond.snapshot();
    await bond.connect(alice).transfer(bob.address, 1n, 1n, 40n);
    await bond.snapshot();

    expect(await bond.balanceOfAt(alice.address, 1n, 1n, 1n)).to.equal(100n);
    expect(await bond.balanceOfAt(bob.address, 1n, 1n, 1n)).to.equal(0n);
    expect(await bond.balanceOfAt(alice.address, 1n, 1n, 2n)).to.equal(60n);
    expect(await bond.balanceOfAt(bob.address, 1n, 1n, 2n)).to.equal(40n);
    expect(await bond.totalSupplyAt(1n, 1n, 2n)).to.equal(100n);

    await bond.connect(bob).redeem(1n, 1n, 10n);
    await bond.snapshot();

    expect(await bond.balanceOfAt(alice.address, 1n, 1n, 2n)).to.equal(60n);
    expect(await bond.balanceOfAt(bob.address, 1n, 1n, 2n)).to.equal(40n);
    expect(await bond.balanceOfAt(bob.address, 1n, 1n, 3n)).to.equal(30n);
    expect(await bond.totalSupplyAt(1n, 1n, 2n)).to.equal(100n);
    // The redeem (supply 100 -> 90) happens BEFORE snapshot #3, so supply at snapshot 3
    // is 90 - now consistent with balanceOfAt(bob, 3) == 30 (previously this read a stale 100).
    expect(await bond.totalSupplyAt(1n, 1n, 3n)).to.equal(90n);
    expect(await bond.totalSupplyAt(1n, 1n, 4n)).to.equal(90n);
  });

  it('enforces secondary-transfer whitelist rules and pause protection', async function () {
    const [admin, alice, bob] = await ethers.getSigners();
    const bondFactory = await ethers.getContractFactory('BondToken');
    const whitelist = await ethers.deployContract('MockWhitelist');
    const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await bond.waitForDeployment();

    await bond.createClass(1n, [{ key: 'name', value: 'Logistics Facility Renovation SPV Bond 2026-01' }]);
    await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2027-03-31' }]);
    await bond.issue(alice.address, 1n, 1n, 100n);

    await whitelist.setWhitelisted(alice.address, true);
    await whitelist.setWhitelisted(bob.address, false);
    await bond.setWhitelist(whitelist.target);

    await expect(
      bond.connect(alice).transfer(bob.address, 1n, 1n, 10n)
    ).to.be.revertedWith('RECIP_NOT_WHITELISTED');

    await whitelist.setWhitelisted(bob.address, true);

    await expect(
      bond.connect(alice).transfer(bob.address, 1n, 1n, 10n)
    ).to.emit(bond, 'Transfer').withArgs(alice.address, bob.address, 1n, 1n, 10n);

    expect(await bond.balanceOf(alice.address, 1n, 1n)).to.equal(90n);
    expect(await bond.balanceOf(bob.address, 1n, 1n)).to.equal(10n);

    await bond.pause();

    await expect(bond.issue(alice.address, 1n, 1n, 1n)).to.be.reverted;
    await expect(bond.connect(alice).transfer(bob.address, 1n, 1n, 1n)).to.be.reverted;
  });
});

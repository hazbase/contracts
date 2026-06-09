import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

describe('BondToken incident-response coverage', function () {
  it('blocks direct and operator-driven secondary transfers after KYC revocation and manual freeze', async function () {
    const [admin, investorA, investorB, operator] = await ethers.getSigners();
    const bondFactory = await ethers.getContractFactory('BondToken');
    const whitelist = await ethers.deployContract('MockWhitelist');
    const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await bond.waitForDeployment();

    await bond.createClass(1n, [{ key: 'name', value: 'Incident Response Bond' }]);
    await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2028-03-31' }]);
    await bond.issue(investorA.address, 1n, 1n, 100n);

    await whitelist.setWhitelisted(investorA.address, true);
    await whitelist.setWhitelisted(investorB.address, true);
    await bond.setWhitelist(await whitelist.getAddress());
    await bond.connect(investorA).setApprovalForAll(operator.address, true);

    await whitelist.setWhitelisted(investorA.address, false);
    await expect(
      bond.connect(investorA).transfer(investorB.address, 1n, 1n, 10n)
    ).to.be.revertedWith('SENDER_NOT_WHITELISTED');
    await expect(
      bond.connect(operator).operatorTransferFrom(investorA.address, investorB.address, 1n, 1n, 10n)
    ).to.be.revertedWith('SENDER_NOT_WHITELISTED');

    await whitelist.setWhitelisted(investorA.address, true);
    await whitelist.setWhitelisted(investorB.address, false);
    await expect(
      bond.connect(investorA).transfer(investorB.address, 1n, 1n, 10n)
    ).to.be.revertedWith('RECIP_NOT_WHITELISTED');
    await expect(
      bond.connect(operator).operatorTransferFrom(investorA.address, investorB.address, 1n, 1n, 10n)
    ).to.be.revertedWith('RECIP_NOT_WHITELISTED');

    await whitelist.setWhitelisted(investorB.address, true);
    await bond.pause();
    await expect(
      bond.connect(investorA).transfer(investorB.address, 1n, 1n, 1n)
    ).to.be.reverted;
    await expect(
      bond.connect(operator).operatorTransferFrom(investorA.address, investorB.address, 1n, 1n, 1n)
    ).to.be.reverted;
  });
});

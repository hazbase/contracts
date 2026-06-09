import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

async function deployFixture() {
  const [admin, treasury, investorA, investorB] = await ethers.getSigners();
  const whitelist = await ethers.deployContract('MockWhitelist');
  const factory = await ethers.getContractFactory('FlexibleToken');
  const token = await upgrades.deployProxy(
    factory,
    ['Incident Common Stock', 'ICS', treasury.address, 1_000n, 5_000n, 0, true, admin.address, []],
    {
      kind: 'uups',
      initializer: 'initialize',
    }
  );
  await token.waitForDeployment();

  await token.grantRole(await token.PAUSER_ROLE(), admin.address);
  await token.grantRole(await token.GUARDIAN_ROLE(), admin.address);  await token.connect(admin).setWhitelist(await whitelist.getAddress());
  await whitelist.setWhitelisted(treasury.address, true);
  await whitelist.setWhitelisted(investorA.address, true);
  await whitelist.setWhitelisted(investorB.address, true);

  await token.connect(treasury).transfer(investorA.address, 600n);
  await token.connect(treasury).transfer(investorB.address, 400n);

  return { admin, treasury, investorA, investorB, whitelist, token };
}

describe('FlexibleToken incident-response coverage', function () {
  it('blocks common-stock transfers after KYC revocation and equity freeze pause', async function () {
    const { admin, investorA, investorB, whitelist, token } = await deployFixture();

    await whitelist.setWhitelisted(investorA.address, false);
    await expect(
      token.connect(investorA).transfer(investorB.address, 10n)
    ).to.be.revertedWith('SENDER_NOT_WL');

    await whitelist.setWhitelisted(investorA.address, true);
    await whitelist.setWhitelisted(investorB.address, false);
    await expect(
      token.connect(investorA).transfer(investorB.address, 10n)
    ).to.be.revertedWith('RECIP_NOT_WL');

    await whitelist.setWhitelisted(investorB.address, true);
    await token.connect(admin).pause();
    await expect(
      token.connect(investorA).transfer(investorB.address, 1n)
    ).to.be.reverted;
  });
});

import { expect } from 'chai';
import { ethers } from 'hardhat';

const CONTRACT_TYPE = ethers.id('MockInitializable');

describe('ContractFactory', function () {
  it('enforces init policy when a version is registered with policy metadata', async function () {
    const [admin, deployer] = await ethers.getSigners();
    const factory = await ethers.deployContract('ContractFactory', [admin.address]);
    const implementation = await ethers.deployContract('MockInitializable');
    const selector = ethers.id('initialize(address,uint256)').slice(0, 10);

    await factory
      .connect(admin)
      .setImplementationWithPolicy(CONTRACT_TYPE, implementation.target, true, true, selector);

    const policy = await factory.getImplementationPolicy(admin.address, CONTRACT_TYPE, 1);
    expect(policy.isSet).to.equal(true);
    expect(policy.cloneable).to.equal(true);
    expect(policy.initRequired).to.equal(true);
    expect(policy.initSelector).to.equal(selector);

    await expect(
      factory.connect(deployer).deployContract(admin.address, CONTRACT_TYPE, '0x')
    ).to.be.revertedWith('init required');

    const initData = implementation.interface.encodeFunctionData('initialize', [admin.address, 7n]);
    const wrongSelector = '0x12345678' + initData.slice(10);
    await expect(
      factory.connect(deployer).deployContract(admin.address, CONTRACT_TYPE, wrongSelector)
    ).to.be.revertedWith('bad init selector');

    const tx = await factory.connect(deployer).deployContract(admin.address, CONTRACT_TYPE, initData);
    const receipt = await tx.wait();
    const event = receipt!.logs
      .map((log) => {
        try {
          return factory.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === 'ContractDeployed');

    expect(event).to.not.equal(undefined);
    const proxy = event!.args.proxy;
    const clone = await ethers.getContractAt('MockInitializable', proxy);
    expect(await clone.admin()).to.equal(admin.address);
    expect(await clone.value()).to.equal(7n);
  });

  it('keeps legacy setImplementation deployments working without policy metadata', async function () {
    const [admin, deployer] = await ethers.getSigners();
    const factory = await ethers.deployContract('ContractFactory', [admin.address]);
    const implementation = await ethers.deployContract('MockInitializable');

    await factory.connect(admin).setImplementation(CONTRACT_TYPE, implementation.target);
    const policy = await factory.getImplementationPolicy(admin.address, CONTRACT_TYPE, 1);
    expect(policy.isSet).to.equal(false);

    const initData = implementation.interface.encodeFunctionData('initialize', [deployer.address, 99n]);
    const tx = await factory.connect(deployer).deployContract(admin.address, CONTRACT_TYPE, initData);
    const receipt = await tx.wait();
    const event = receipt!.logs
      .map((log) => {
        try {
          return factory.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .find((parsed) => parsed?.name === 'ContractDeployed');

    expect(event).to.not.equal(undefined);
    const proxy = event!.args.proxy;
    const clone = await ethers.getContractAt('MockInitializable', proxy);
    expect(await clone.admin()).to.equal(deployer.address);
    expect(await clone.value()).to.equal(99n);
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

async function deployWhitelistFixture() {
  const [admin, basicUser, zkUser, cohortUser] = await ethers.getSigners();
  const verifier = await ethers.deployContract('MockVerifier');
  const factory = await ethers.getContractFactory('Whitelist');
  const root = ethers.keccak256(ethers.toUtf8Bytes('incident-revocation-root-2026-03-19'));
  const whitelist = await upgrades.deployProxy(
    factory,
    [admin.address, root, await verifier.getAddress(), []],
    {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    }
  );
  await whitelist.waitForDeployment();
  return { admin, basicUser, zkUser, cohortUser, verifier, whitelist, root };
}

describe('Whitelist incident-response coverage', function () {
  it('revokes Basic and ZK users individually and in batch for incident response', async function () {
    const { basicUser, zkUser, cohortUser, whitelist, root } = await deployWhitelistFixture();

    await whitelist.addBatch([basicUser.address, cohortUser.address]);
    const zkSignals = [0n, BigInt(root), 91n, BigInt(zkUser.address), 0n, 0n] as const;
    await whitelist.addWithVerify(zkUser.address, [0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n], zkSignals);

    expect(await whitelist.isWhitelisted(basicUser.address)).to.equal(true);
    expect(await whitelist.isWhitelisted(zkUser.address)).to.equal(true);
    expect(await whitelist.kycLevel(zkUser.address)).to.equal(2n);

    await whitelist.remove(zkUser.address);
    expect(await whitelist.isWhitelisted(zkUser.address)).to.equal(false);
    expect(await whitelist.kycLevel(zkUser.address)).to.equal(0n);

    await whitelist.removeBatch([basicUser.address, cohortUser.address]);
    expect(await whitelist.isWhitelisted(basicUser.address)).to.equal(false);
    expect(await whitelist.isWhitelisted(cohortUser.address)).to.equal(false);

    await whitelist.add(zkUser.address);
    expect(await whitelist.isWhitelisted(zkUser.address)).to.equal(true);
    expect(await whitelist.kycLevel(zkUser.address)).to.equal(1n);
  });
});

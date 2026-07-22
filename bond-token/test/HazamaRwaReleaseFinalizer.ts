import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

const ERC20 = 1;
const releaseTypes = {
  HazamaReleaseAttestation: [
    { name: 'templateId', type: 'string' },
    { name: 'orderId', type: 'string' },
    { name: 'orderKey', type: 'bytes32' },
    { name: 'termsHash', type: 'bytes32' },
    { name: 'sourceChainId', type: 'uint256' },
    { name: 'sourceContract', type: 'address' },
    { name: 'destinationNetwork', type: 'string' },
    { name: 'lockExpiresAt', type: 'uint64' },
    { name: 'observedLiquidHeight', type: 'uint256' },
    { name: 'observedLiquidBlockHash', type: 'bytes32' },
    { name: 'reasonCode', type: 'bytes32' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'expiresAt', type: 'uint64' },
  ],
};

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

async function fixture() {
  const [admin, backingOwner, caller] = await ethers.getSigners();
  const approver1 = ethers.Wallet.createRandom();
  const approver2 = ethers.Wallet.createRandom();
  const manager = await ethers.deployContract('GenericRwaBackingLockManager', [admin.address]);
  await manager.waitForDeployment();
  const token = await ethers.deployContract('MockERC20');
  await token.waitForDeployment();
  await token.mint(backingOwner.address, 100n);
  await token.connect(backingOwner).approve(await manager.getAddress(), 100n);

  const releaseDelay = 300n;
  const finalizer = await ethers.deployContract('HazamaRwaReleaseFinalizer', [
    admin.address,
    await manager.getAddress(),
    releaseDelay,
  ]);
  await finalizer.waitForDeployment();
  await finalizer.setHazamaApprover(approver1.address, true);
  await finalizer.setHazamaApprover(approver2.address, true);
  await finalizer.setHazamaThreshold(2n);
  const releaserRole = await manager.RELEASER_ROLE();
  await manager.grantRole(releaserRole, await finalizer.getAddress());

  const orderLabel = 'release-order-1';
  const orderKey = id(orderLabel);
  const termsHash = id('release-terms-1');
  const lockExpiresAt = BigInt(await time.latest()) + 600n;
  await manager.lock(
    orderKey,
    ERC20,
    await token.getAddress(),
    backingOwner.address,
    0n,
    0n,
    10n,
    id('liquid-rwa-asset'),
    termsHash,
    lockExpiresAt,
  );

  const domain = {
    name: 'HAZAMA Release Attestation',
    version: '1',
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await finalizer.getAddress(),
  };
  const reasonCode = id('order_expired');

  async function proof(overrides: Record<string, unknown> = {}) {
    const observedAt = lockExpiresAt + releaseDelay;
    const attestation = {
      templateId: 'liquid-no-delivery-release-v1',
      orderId: orderLabel,
      orderKey,
      termsHash,
      sourceChainId: domain.chainId,
      sourceContract: await manager.getAddress(),
      destinationNetwork: 'liquidtestnet',
      lockExpiresAt,
      observedLiquidHeight: 2_525_000n,
      observedLiquidBlockHash: id('liquid-release-cutoff'),
      reasonCode,
      observedAt,
      expiresAt: observedAt + 3600n,
      ...overrides,
    };
    return {
      attestation,
      signatures: [
        await approver1.signTypedData(domain, releaseTypes, attestation),
        await approver2.signTypedData(domain, releaseTypes, attestation),
      ],
    };
  }

  return {
    admin,
    backingOwner,
    caller,
    approver1,
    approver2,
    manager,
    token,
    finalizer,
    releaseDelay,
    orderKey,
    reasonCode,
    lockExpiresAt,
    proof,
    releaserRole,
  };
}

describe('HazamaRwaReleaseFinalizer', function () {
  it('rejects release before the lock timeout and delay', async function () {
    const { caller, finalizer, orderKey, reasonCode, proof } = await fixture();
    const releaseProof = await proof();
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        releaseProof.signatures,
      ),
    ).to.be.revertedWith('RELEASE_DELAY_ACTIVE');
  });

  it('allows any caller to release after timeout with a 2-of-2 proof', async function () {
    const { admin, backingOwner, caller, finalizer, manager, token, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof, releaserRole } = await fixture();
    await manager.revokeRole(releaserRole, admin.address);
    await time.increaseTo(lockExpiresAt + releaseDelay);
    const releaseProof = await proof();

    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        releaseProof.signatures,
      ),
    )
      .to.emit(finalizer, 'BackingReleaseFinalized')
      .and.to.emit(manager, 'BackingReleased');

    expect((await manager.getLock(orderKey)).status).to.equal(2n);
    expect(await token.balanceOf(backingOwner.address)).to.equal(100n);
  });

  it('rejects insufficient, duplicate, and unapproved signers', async function () {
    const { caller, approver1, finalizer, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof } = await fixture();
    await time.increaseTo(lockExpiresAt + releaseDelay);
    const releaseProof = await proof();

    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation],
        [releaseProof.signatures[0]],
      ),
    ).to.be.revertedWith('HAZAMA_QUORUM_NOT_MET');
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        [releaseProof.signatures[0], releaseProof.signatures[0]],
      ),
    ).to.be.revertedWith('HAZAMA_DUPLICATE_SIGNER');

    const outsider = ethers.Wallet.createRandom();
    const outsiderSignature = await outsider.signTypedData(
      {
        name: 'HAZAMA Release Attestation',
        version: '1',
        chainId: (await ethers.provider.getNetwork()).chainId,
        verifyingContract: await finalizer.getAddress(),
      },
      releaseTypes,
      releaseProof.attestation,
    );
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        [releaseProof.signatures[0], outsiderSignature],
      ),
    ).to.be.revertedWith('HAZAMA_APPROVER_INVALID');
    expect(approver1.address).to.not.equal(outsider.address);
  });

  it('rejects a proof that does not match the locked terms or canonical context', async function () {
    const { caller, finalizer, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof } = await fixture();
    await time.increaseTo(lockExpiresAt + releaseDelay);
    const mismatch = await proof({ termsHash: id('wrong-terms') });
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [mismatch.attestation, mismatch.attestation],
        mismatch.signatures,
      ),
    ).to.be.revertedWith('ATTEST_TERMS_HASH');

    const differentContext = await proof({ observedLiquidBlockHash: id('different-cutoff') });
    const first = await proof();
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [first.attestation, differentContext.attestation],
        [first.signatures[0], differentContext.signatures[1]],
      ),
    ).to.be.revertedWith('HAZAMA_ATTESTATION_MISMATCH');
  });
});

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
    { name: 'reservationHash', type: 'bytes32' },
    { name: 'deliveryOutpointHash', type: 'bytes32' },
    { name: 'invalidationTxid', type: 'bytes32' },
    { name: 'invalidationVout', type: 'uint256' },
    { name: 'liquidAssetId', type: 'bytes32' },
    { name: 'liquidAmount', type: 'uint256' },
    { name: 'inventoryScriptHash', type: 'bytes32' },
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

async function fixture(options: { active?: boolean } = {}) {
  const [admin, backingOwner, caller] = await ethers.getSigners();
  const approvers = [
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
    ethers.Wallet.createRandom(),
  ];
  const manager = await ethers.deployContract('GenericRwaBackingLockManager', [admin.address]);
  await manager.waitForDeployment();
  const token = await ethers.deployContract('MockERC20');
  await token.waitForDeployment();
  await token.mint(backingOwner.address, 100n);
  await token.connect(backingOwner).approve(await manager.getAddress(), 100n);

  const releaseDelay = 300n;
  const finalizer = await ethers.deployContract('HazamaRwaReleaseFinalizerV2', [
    admin.address,
    await manager.getAddress(),
    releaseDelay,
  ]);
  await finalizer.waitForDeployment();
  for (const approver of approvers) {
    await finalizer.setHazamaApprover(approver.address, true);
  }
  await finalizer.setHazamaThreshold(2n);
  const releaserRole = await manager.RELEASER_ROLE();
  await manager.grantRole(releaserRole, await finalizer.getAddress());
  if (options.active !== false) await finalizer.unpause();

  const orderLabel = 'release-order-v2';
  const orderKey = id(orderLabel);
  const termsHash = id('release-terms-v2');
  const liquidAssetId = id('liquid-rwa-asset');
  const lockExpiresAt = BigInt(await time.latest()) + 600n;
  await manager.lock(
    orderKey,
    ERC20,
    await token.getAddress(),
    backingOwner.address,
    0n,
    0n,
    10n,
    liquidAssetId,
    termsHash,
    lockExpiresAt,
  );

  const domain = {
    name: 'HAZAMA Release Attestation',
    version: '2',
    chainId: (await ethers.provider.getNetwork()).chainId,
    verifyingContract: await finalizer.getAddress(),
  };
  const reasonCode = id('liquid_reservation_invalidated');

  async function proof(overrides: Record<string, unknown> = {}) {
    const observedAt = lockExpiresAt + releaseDelay;
    const attestation = {
      templateId: 'liquid-reservation-invalidation-release-v2',
      orderId: orderLabel,
      orderKey,
      termsHash,
      sourceChainId: domain.chainId,
      sourceContract: await manager.getAddress(),
      destinationNetwork: 'liquidtestnet',
      lockExpiresAt,
      reservationHash: id('reservation'),
      deliveryOutpointHash: id('delivery-outpoint'),
      invalidationTxid: id('invalidation-tx'),
      invalidationVout: 1n,
      liquidAssetId,
      liquidAmount: 10n,
      inventoryScriptHash: id('inventory-script'),
      observedLiquidHeight: 2_525_000n,
      observedLiquidBlockHash: id('invalidation-block'),
      reasonCode,
      observedAt,
      expiresAt: observedAt + 3600n,
      ...overrides,
    };
    return {
      attestation,
      signatures: await Promise.all(
        approvers.slice(0, 2).map((approver) => approver.signTypedData(domain, releaseTypes, attestation)),
      ),
    };
  }

  return {
    admin,
    backingOwner,
    caller,
    approvers,
    manager,
    token,
    finalizer,
    releaseDelay,
    orderKey,
    reasonCode,
    lockExpiresAt,
    proof,
    releaserRole,
    domain,
  };
}

describe('HazamaRwaReleaseFinalizerV2', function () {
  it('is paused by default until an explicit activation', async function () {
    const { finalizer } = await fixture({ active: false });
    expect(await finalizer.paused()).to.equal(true);
    expect(await finalizer.RELEASE_TEMPLATE_HASH()).to.equal(id('liquid-reservation-invalidation-release-v2'));
    expect(await finalizer.RELEASE_REASON_CODE()).to.equal(id('liquid_reservation_invalidated'));
  });

  it('rejects release before the lock timeout and release delay', async function () {
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

  it('allows any caller to release with a 2-of-3 invalidation proof', async function () {
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
    const { caller, approvers, finalizer, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof, domain } = await fixture();
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
    const outsiderSignature = await outsider.signTypedData(domain, releaseTypes, releaseProof.attestation);
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        [releaseProof.signatures[0], outsiderSignature],
      ),
    ).to.be.revertedWith('HAZAMA_APPROVER_INVALID');
    expect(approvers[0].address).to.not.equal(outsider.address);
  });

  it('rejects changed invalidation evidence and zero safety commitments', async function () {
    const { caller, finalizer, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof } = await fixture();
    await time.increaseTo(lockExpiresAt + releaseDelay);
    const first = await proof();
    const different = await proof({ invalidationTxid: id('different-invalidation') });
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [first.attestation, different.attestation],
        [first.signatures[0], different.signatures[1]],
      ),
    ).to.be.revertedWith('HAZAMA_ATTESTATION_MISMATCH');

    const zero = await proof({ reservationHash: ethers.ZeroHash });
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [zero.attestation, zero.attestation],
        zero.signatures,
      ),
    ).to.be.revertedWith('ATTEST_RESERVATION');
  });

  it('accepts only the reservation invalidation release reason', async function () {
    const { caller, finalizer, orderKey, lockExpiresAt, releaseDelay, proof } = await fixture();
    await time.increaseTo(lockExpiresAt + releaseDelay);
    const wrongReason = id('different-release-reason');
    const releaseProof = await proof({ reasonCode: wrongReason });
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        wrongReason,
        [releaseProof.attestation, releaseProof.attestation],
        releaseProof.signatures,
      ),
    ).to.be.revertedWith('REASON_INVALID');
  });

  it('honors the emergency pause', async function () {
    const { caller, finalizer, orderKey, reasonCode, lockExpiresAt, releaseDelay, proof } = await fixture();
    await time.increaseTo(lockExpiresAt + releaseDelay);
    await finalizer.pause();
    const releaseProof = await proof();
    await expect(
      finalizer.connect(caller).releaseWithAttestations(
        orderKey,
        reasonCode,
        [releaseProof.attestation, releaseProof.attestation],
        releaseProof.signatures,
      ),
    ).to.be.revertedWithCustomError(finalizer, 'EnforcedPause');
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function digest(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

async function deployFixture(withTransferPolicy = true) {
  const [admin, issuer, guardian, redeemer, recipient, nextHolder, outsider] = await ethers.getSigners();
  const policy = await ethers.deployContract('MockPhysicalAssetTransferPolicy');
  await policy.waitForDeployment();

  const factory = await ethers.getContractFactory('PhysicalAssetToken');
  const token = await upgrades.deployProxy(
    factory,
    [
      'Ecoro Physical Asset Rights',
      'ECO-PAR',
      'https://example.test/assets/',
      digest('tenant:ecoro'),
      admin.address,
      issuer.address,
      guardian.address,
      redeemer.address,
      withTransferPolicy ? await policy.getAddress() : ethers.ZeroAddress,
    ],
    { kind: 'transparent', initializer: 'initialize', unsafeAllow: ['constructor'] },
  );
  await token.waitForDeployment();

  return { admin, issuer, guardian, redeemer, recipient, nextHolder, outsider, policy, token };
}

describe('PhysicalAssetToken', function () {
  it('issues exactly one immutable right for one salted physical-asset commitment', async function () {
    const { issuer, recipient, token } = await deployFixture(false);
    const commitment = digest('salted-card-serial');
    const rightsHash = digest('delivery-claim-v1');
    const metadataHash = digest('metadata-v1');
    const tokenId = BigInt(commitment);

    await expect(token.connect(issuer).issue(recipient.address, commitment, rightsHash, metadataHash))
      .to.emit(token, 'PhysicalAssetIssued')
      .withArgs(tokenId, commitment, recipient.address, rightsHash, metadataHash);

    expect(await token.ownerOf(tokenId)).to.equal(recipient.address);
    const record = await token.assetRecord(tokenId);
    expect(record.assetCommitment).to.equal(commitment);
    expect(record.rightsHash).to.equal(rightsHash);
    expect(record.metadataHash).to.equal(metadataHash);
    expect(record.status).to.equal(1n);
    expect(await token.tokenURI(tokenId)).to.equal(`https://example.test/assets/${tokenId}`);

    await expect(
      token.connect(issuer).issue(recipient.address, commitment, rightsHash, metadataHash),
    ).to.be.revertedWithCustomError(token, 'CommitmentAlreadyIssued');
  });

  it('issues to an approved contract-based custody account', async function () {
    const { issuer, policy, token } = await deployFixture(false);
    const commitment = digest('contract-custody-item');
    const rightsHash = digest('contract-custody-rights');
    const metadataHash = digest('contract-custody-metadata');

    await expect(token.connect(issuer).issue(await policy.getAddress(), commitment, rightsHash, metadataHash))
      .to.emit(token, 'PhysicalAssetIssued');
    expect(await token.ownerOf(BigInt(commitment))).to.equal(await policy.getAddress());
  });

  it('requires the issuer role and rejects empty commitments and document digests', async function () {
    const { issuer, outsider, recipient, token } = await deployFixture(false);
    const commitment = digest('asset');
    const rightsHash = digest('rights');
    const metadataHash = digest('metadata');

    await expect(
      token.connect(outsider).issue(recipient.address, commitment, rightsHash, metadataHash),
    ).to.be.revertedWithCustomError(token, 'AccessControlUnauthorizedAccount');
    await expect(
      token.connect(issuer).issue(recipient.address, ethers.ZeroHash, rightsHash, metadataHash),
    ).to.be.revertedWithCustomError(token, 'CommitmentZero');
    await expect(
      token.connect(issuer).issue(recipient.address, commitment, ethers.ZeroHash, metadataHash),
    ).to.be.revertedWithCustomError(token, 'DigestZero');
  });

  it('allows transfers only between approved accounts and blocks a frozen item', async function () {
    const { issuer, guardian, recipient, nextHolder, outsider, policy, token } = await deployFixture();
    const commitment = digest('transferable-asset');
    const tokenId = BigInt(commitment);
    await token.connect(issuer).issue(recipient.address, commitment, digest('rights'), digest('metadata'));
    await policy.setApproved(recipient.address, true);
    await policy.setApproved(nextHolder.address, true);

    await token.connect(recipient).transferFrom(recipient.address, nextHolder.address, tokenId);
    expect(await token.ownerOf(tokenId)).to.equal(nextHolder.address);

    await expect(
      token.connect(nextHolder).transferFrom(nextHolder.address, outsider.address, tokenId),
    ).to.be.revertedWithCustomError(token, 'TransferNotAllowed');

    await token.connect(guardian).freeze(tokenId, digest('custody-exception'));
    await expect(
      token.connect(nextHolder).transferFrom(nextHolder.address, recipient.address, tokenId),
    ).to.be.revertedWithCustomError(token, 'AssetNotActive');
    await token.connect(guardian).unfreeze(tokenId);
    await token.connect(nextHolder).transferFrom(nextHolder.address, recipient.address, tokenId);
  });

  it('disables transfers when no approved-account policy is configured', async function () {
    const { issuer, recipient, nextHolder, token } = await deployFixture(false);
    const commitment = digest('non-transferable-asset');
    const tokenId = BigInt(commitment);
    await token.connect(issuer).issue(recipient.address, commitment, digest('rights'), digest('metadata'));

    await expect(
      token.connect(recipient).transferFrom(recipient.address, nextHolder.address, tokenId),
    ).to.be.revertedWithCustomError(token, 'TransferNotAllowed');
  });

  it('burns the right only through the redemption role while retaining the audit record', async function () {
    const { issuer, guardian, redeemer, recipient, token } = await deployFixture(false);
    const commitment = digest('redeemable-asset');
    const tokenId = BigInt(commitment);
    const redemptionId = digest('redemption-request');
    const fulfillmentEvidenceHash = digest('delivery-receipt');
    await token.connect(issuer).issue(recipient.address, commitment, digest('rights'), digest('metadata'));
    await token.connect(guardian).freeze(tokenId, digest('redemption-pending'));

    await expect(token.connect(redeemer).redeem(tokenId, redemptionId, fulfillmentEvidenceHash))
      .to.emit(token, 'PhysicalAssetRedeemed')
      .withArgs(tokenId, redemptionId, fulfillmentEvidenceHash);

    await expect(token.ownerOf(tokenId)).to.be.revertedWithCustomError(token, 'ERC721NonexistentToken');
    const record = await token.assetRecord(tokenId);
    expect(record.status).to.equal(3n);
    expect(record.redemptionId).to.equal(redemptionId);
    expect(record.fulfillmentEvidenceHash).to.equal(fulfillmentEvidenceHash);
  });

  it('pauses issuance, transfer, and redemption without losing the recorded item', async function () {
    const { admin, issuer, redeemer, recipient, token } = await deployFixture(false);
    const commitment = digest('paused-asset');
    const tokenId = BigInt(commitment);
    await token.connect(issuer).issue(recipient.address, commitment, digest('rights'), digest('metadata'));
    await token.connect(admin).pause();

    await expect(
      token.connect(redeemer).redeem(tokenId, digest('redemption'), digest('receipt')),
    ).to.be.revertedWithCustomError(token, 'EnforcedPause');
    expect((await token.assetRecord(tokenId)).status).to.equal(1n);
  });
});

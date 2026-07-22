import { expect } from 'chai';
import { ethers } from 'hardhat';
import { anyValue } from '@nomicfoundation/hardhat-chai-matchers/withArgs';

const ERC3475 = 0;
const ERC20 = 1;

const redemptionAttestationTypes = {
  HazamaRedemptionAttestation: [
    { name: 'templateId', type: 'string' },
    { name: 'redemptionRequestId', type: 'string' },
    { name: 'assetBindingId', type: 'string' },
    { name: 'termsHash', type: 'bytes32' },
    { name: 'sourceChainId', type: 'uint256' },
    { name: 'sourceContract', type: 'address' },
    { name: 'tokenStandard', type: 'string' },
    { name: 'token', type: 'address' },
    { name: 'classId', type: 'uint256' },
    { name: 'nonceId', type: 'uint256' },
    { name: 'holderEvmAddress', type: 'address' },
    { name: 'liquidNetwork', type: 'string' },
    { name: 'liquidTxid', type: 'string' },
    { name: 'recoveryVout', type: 'uint32' },
    { name: 'recoveryAssetId', type: 'string' },
    { name: 'recoveryAmount', type: 'uint256' },
    { name: 'vaultAddressHash', type: 'bytes32' },
    { name: 'confirmations', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'expiresAt', type: 'uint64' },
  ],
};

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function hex(value: string) {
  return id(value).slice(2);
}

async function fixture() {
  const [admin, approverOne, approverTwo, executor, holder, other] = await ethers.getSigners();
  const manager = await ethers.deployContract('GenericRwaRedemptionManager', [admin.address]);
  await manager.waitForDeployment();

  const finalizer = await ethers.deployContract('HazamaRwaRedemptionFinalizer', [
    admin.address,
    await manager.getAddress(),
  ]);
  await finalizer.waitForDeployment();

  const erc20 = await ethers.deployContract('MockERC20');
  await erc20.waitForDeployment();

  await manager.grantRole(await manager.RECORDER_ROLE(), await finalizer.getAddress());
  await finalizer.setHazamaApprover(approverOne.address, true);
  await finalizer.setHazamaApprover(approverTwo.address, true);
  await finalizer.setHazamaThreshold(2);

  return { admin, approverOne, approverTwo, executor, holder, other, manager, finalizer, erc20 };
}

async function signedAttestation(input: {
  finalizer: any;
  signer: any;
  record: Record<string, unknown>;
  redemptionRequestId: string;
  expiresAt?: bigint;
  override?: Record<string, unknown>;
}) {
  const network = await ethers.provider.getNetwork();
  const message = {
    templateId: 'liquid-recovery-to-evm-redemption-v1',
    redemptionRequestId: input.redemptionRequestId,
    assetBindingId: 'asset-binding-test',
    termsHash: input.record.termsHash,
    sourceChainId: network.chainId,
    sourceContract: await input.finalizer.getAddress(),
    tokenStandard: input.record.tokenStandard === ERC3475 ? 'ERC3475' : 'ERC20',
    token: input.record.token,
    classId: input.record.classId,
    nonceId: input.record.nonceId,
    holderEvmAddress: input.record.holder,
    liquidNetwork: 'liquidtestnet',
    liquidTxid: hex('liquid-recovery'),
    recoveryVout: input.record.liquidRecoveryVout,
    recoveryAssetId: hex('liquid-asset'),
    recoveryAmount: input.record.amount,
    vaultAddressHash: id('redemption-vault'),
    confirmations: 2,
    observedAt: 1_000_000_000,
    expiresAt: input.expiresAt ?? 4_000_000_000n,
    ...input.override,
  };
  const signature = await input.signer.signTypedData({
    name: 'HAZAMA Redemption Attestation',
    version: '1',
    chainId: network.chainId,
    verifyingContract: await input.finalizer.getAddress(),
  }, redemptionAttestationTypes, message);
  return { message, signature };
}

describe('HazamaRwaRedemptionFinalizer', function () {
  it('lets any caller finalize a redemption once the HAZAMA threshold is met', async function () {
    const { approverOne, approverTwo, executor, holder, manager, finalizer, erc20 } = await fixture();
    const redemptionRequestId = 'redemption:public-finalize';
    const record = {
      redemptionId: id(redemptionRequestId),
      tokenStandard: ERC20,
      token: await erc20.getAddress(),
      holder: holder.address,
      classId: 0n,
      nonceId: 0n,
      amount: 10n,
      liquidAssetId: id('liquid-asset'),
      liquidRecoveryTxid: id('liquid-recovery'),
      liquidRecoveryVout: 3,
      termsHash: id('redemption-terms'),
    };
    const first = await signedAttestation({ finalizer, signer: approverOne, record, redemptionRequestId });
    const second = await signedAttestation({ finalizer, signer: approverTwo, record, redemptionRequestId });

    await expect(finalizer.connect(executor).finalizeRedemption(
      record,
      [first.message, second.message],
      [first.signature, second.signature],
    ))
      .to.emit(finalizer, 'RedemptionFinalized')
      .withArgs(record.redemptionId, anyValue, executor.address, 2);

    const stored = await manager.getRedemption(record.redemptionId);
    expect(stored.status).to.equal(1n);
    expect(stored.holder).to.equal(holder.address);
    expect(stored.amount).to.equal(10n);
    expect(stored.evidenceHash).to.not.equal(ethers.ZeroHash);
  });

  it('rejects an insufficient, duplicated, expired, or mismatched quorum proof', async function () {
    const { approverOne, approverTwo, executor, holder, finalizer, erc20 } = await fixture();
    const redemptionRequestId = 'redemption:invalid-proof';
    const record = {
      redemptionId: id(redemptionRequestId),
      tokenStandard: ERC20,
      token: await erc20.getAddress(),
      holder: holder.address,
      classId: 0n,
      nonceId: 0n,
      amount: 10n,
      liquidAssetId: id('liquid-asset'),
      liquidRecoveryTxid: id('liquid-recovery'),
      liquidRecoveryVout: 3,
      termsHash: id('redemption-terms'),
    };
    const first = await signedAttestation({ finalizer, signer: approverOne, record, redemptionRequestId });
    const second = await signedAttestation({ finalizer, signer: approverTwo, record, redemptionRequestId });

    await expect(finalizer.connect(executor).finalizeRedemption(record, [first.message], [first.signature]))
      .to.be.revertedWith('HAZAMA_QUORUM_NOT_MET');

    await expect(finalizer.connect(executor).finalizeRedemption(
      record,
      [first.message, first.message],
      [first.signature, first.signature],
    )).to.be.revertedWith('HAZAMA_DUPLICATE_SIGNER');

    const expired = await signedAttestation({
      finalizer,
      signer: approverOne,
      record,
      redemptionRequestId,
      expiresAt: 1n,
    });
    await expect(finalizer.connect(executor).finalizeRedemption(
      record,
      [expired.message, second.message],
      [expired.signature, second.signature],
    )).to.be.revertedWith('ATTEST_EXPIRED');

    const mismatched = await signedAttestation({
      finalizer,
      signer: approverOne,
      record,
      redemptionRequestId,
      override: { recoveryAmount: 11n },
    });
    await expect(finalizer.connect(executor).finalizeRedemption(
      record,
      [mismatched.message, second.message],
      [mismatched.signature, second.signature],
    )).to.be.revertedWith('ATTEST_AMOUNT');
  });
});

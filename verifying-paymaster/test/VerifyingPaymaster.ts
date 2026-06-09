import { expect } from 'chai';
import { ethers } from 'hardhat';

const coder = ethers.AbiCoder.defaultAbiCoder();
const PLACEHOLDER_SIG_LEN = 65;

function baseUserOp(sender: string, paymasterAndData: string, overrides: Partial<Record<string, unknown>> = {}) {
  return {
    sender,
    nonce: 0n,
    initCode: '0x',
    callData: '0x12345678',
    callGasLimit: 500_000n,
    verificationGasLimit: 500_000n,
    preVerificationGas: 50_000n,
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
    paymasterAndData,
    signature: '0x',
    ...overrides,
  };
}

async function buildSponsoredUserOp(
  paymaster: any,
  sponsorSigner: { signMessage: (message: Uint8Array) => Promise<string> },
  sender: string,
  validUntil: bigint,
  validAfter: bigint,
  userOpOverrides: Partial<Record<string, unknown>> = {},
) {
  const windowData = coder.encode(['uint48', 'uint48'], [validUntil, validAfter]);
  const placeholder = ethers.concat([
    paymaster.target,
    windowData,
    `0x${'00'.repeat(PLACEHOLDER_SIG_LEN)}`,
  ]);
  const draftUserOp = baseUserOp(sender, placeholder, userOpOverrides);
  const hash = await paymaster.getHash(draftUserOp, validUntil, validAfter);
  const signature = await sponsorSigner.signMessage(ethers.getBytes(hash));
  const paymasterAndData = ethers.concat([paymaster.target, windowData, signature]);
  return {
    userOp: baseUserOp(sender, paymasterAndData, userOpOverrides),
    signature,
  };
}

describe('VerifyingPaymaster guardrails', function () {
  async function deployFixture() {
    const [deployer, entryPoint, verifyingSigner, sender, other] = await ethers.getSigners();
    const paymaster = await ethers.deployContract('VerifyingPaymaster', [entryPoint.address, verifyingSigner.address]);
    await paymaster.waitForDeployment();
    return { deployer, entryPoint, verifyingSigner, sender, other, paymaster };
  }

  it('does not increment senderNonce on invalid sponsorship signatures', async function () {
    const { entryPoint, other, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, other, sender.address, 3_000n, 10n);

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
  });

  it('increments senderNonce exactly once after a valid sponsorship signature', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 3_000n, 10n);

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(1n);
  });

  it('rejects replayed sponsorships after the sender nonce advances and leaves nonce unchanged', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 3_000n, 10n);

    const validResult = await paymaster.connect(entryPoint).validatePaymasterUserOp.staticCall(userOp, ethers.ZeroHash, 0);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(1n);

    const replayResult = await paymaster.connect(entryPoint).validatePaymasterUserOp.staticCall(userOp, ethers.ZeroHash, 0);
    expect(replayResult[1]).to.not.equal(validResult[1]);

    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(1n);
  });

  it('keeps validity window parsing unchanged for accepted sponsorships', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const validUntil = 3_600n;
    const validAfter = 456n;
    const { userOp, signature } = await buildSponsoredUserOp(
      paymaster,
      verifyingSigner,
      sender.address,
      validUntil,
      validAfter,
    );

    const [parsedUntil, parsedAfter, parsedSig] = await paymaster.parsePaymasterAndData(userOp.paymasterAndData);
    expect(parsedUntil).to.equal(validUntil);
    expect(parsedAfter).to.equal(validAfter);
    expect(parsedSig).to.equal(signature);

    await expect(paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0)).to.not.be.reverted;
  });

  it('rejects sponsorships that exceed the validity window guardrail', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 10_000n, 10n);

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
  });

  it('rejects sponsorships that exceed the call gas limit guardrail', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 3_000n, 10n, {
      callGasLimit: 1_000_001n,
    });

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
  });

  it('rejects sponsorships that exceed the verification gas limit guardrail', async function () {
    const { entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 3_000n, 10n, {
      verificationGasLimit: 1_000_001n,
    });

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
  });

  it('does not sponsor while paused', async function () {
    const { deployer, entryPoint, verifyingSigner, sender, paymaster } = await deployFixture();
    await paymaster.connect(deployer).pause();
    const { userOp } = await buildSponsoredUserOp(paymaster, verifyingSigner, sender.address, 3_000n, 10n);

    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
    await paymaster.connect(entryPoint).validatePaymasterUserOp(userOp, ethers.ZeroHash, 0);
    expect(await paymaster.senderNonce(sender.address)).to.equal(0n);
  });
});

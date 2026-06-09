import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

const coder = ethers.AbiCoder.defaultAbiCoder();
const OWNER_USER_OP_DOMAIN = ethers.keccak256(ethers.toUtf8Bytes("hazbase.passkey.owner.userop.v1"));
const SIG_FAILURE_MASK = (1n << 160n) - 1n;

function packValidationData(sigFailed: boolean, validUntil: bigint, validAfter = 0n) {
  return (sigFailed ? 1n : 0n) | (validUntil << 160n) | (validAfter << 208n);
}

function buildUserOp(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    sender: ethers.ZeroAddress,
    nonce: 0n,
    initCode: "0x",
    callData: "0x",
    callGasLimit: 500_000n,
    verificationGasLimit: 500_000n,
    preVerificationGas: 50_000n,
    maxFeePerGas: 0n,
    maxPriorityFeePerGas: 0n,
    paymasterAndData: "0x",
    signature: "0x",
    ...overrides,
  };
}

async function buildOwnerPayload(params: {
  authorizer: { signMessage: (message: Uint8Array) => Promise<string> };
  validatorAddress: string;
  accountAddress: string;
  ownerConfigHash: string;
  userOpHash: string;
  chainId: bigint;
  validAfter?: number;
  validUntil?: number;
}) {
  const validAfter = params.validAfter ?? Math.floor(Date.now() / 1000) - 30;
  const validUntil = params.validUntil ?? validAfter + 600;
  const digest = ethers.keccak256(
    coder.encode(
      ["bytes32", "uint256", "address", "address", "bytes32", "bytes32", "uint48", "uint48"],
      [
        OWNER_USER_OP_DOMAIN,
        params.chainId,
        params.validatorAddress,
        params.accountAddress,
        params.ownerConfigHash,
        params.userOpHash,
        validUntil,
        validAfter,
      ],
    ),
  );
  const signed = await params.authorizer.signMessage(ethers.getBytes(digest));
  return coder.encode(
    ["uint48", "uint48", "bytes32", "bytes"],
    [validUntil, validAfter, params.ownerConfigHash, signed],
  );
}

async function buildOwnerAccountSignature(params: {
  authorizer: { signMessage: (message: Uint8Array) => Promise<string> };
  validatorAddress: string;
  accountAddress: string;
  ownerConfigHash: string;
  userOpHash: string;
  chainId: bigint;
  validAfter?: number;
  validUntil?: number;
}) {
  const payload = await buildOwnerPayload(params);
  return coder.encode(["uint8", "bytes"], [0, payload]);
}

async function buildSessionAccountSignature(
  signer: { signMessage: (message: Uint8Array) => Promise<string> },
  userOpHash: string,
) {
  const signed = await signer.signMessage(ethers.getBytes(userOpHash));
  return coder.encode(["uint8", "bytes"], [1, signed]);
}

describe("SmartAccountV2 bundler-safe validation", function () {
  async function deployFixture() {
    const [authorizer, safe, entryPoint, session] = await ethers.getSigners();
    const validator = await ethers.deployContract("PasskeyOwnerValidatorV2", [authorizer.address]);
    const ownerConfig = coder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        ethers.keccak256(ethers.toUtf8Bytes("cred-v2")),
        ethers.keccak256(ethers.toUtf8Bytes("passkey.hazbase.com")),
        ethers.keccak256(ethers.toUtf8Bytes("pubkey-x")),
        ethers.keccak256(ethers.toUtf8Bytes("pubkey-y")),
      ],
    );

    // The implementation disables initializers in its constructor (security hardening), so it must be
    // initialized through a proxy — exactly like production AccountFactoryV2 clones. Deploy via UUPS proxy.
    const SmartAccountV2 = await ethers.getContractFactory("SmartAccountV2");
    const account = await upgrades.deployProxy(
      SmartAccountV2,
      [validator.target, ownerConfig, entryPoint.address, safe.address],
      { kind: "uups", initializer: "initialize", unsafeAllow: ["delegatecall"] },
    );
    await account.waitForDeployment();

    const receiver = await ethers.deployContract("MockReceiver");
    return {
      authorizer,
      safe,
      entryPoint,
      session,
      validator,
      account,
      receiver,
      ownerConfig,
      ownerConfigHash: await validator.configHash(ownerConfig),
      chainId: BigInt((await ethers.provider.getNetwork()).chainId),
    };
  }

  async function execAsOwner(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    innerCallData: string,
    label: string,
  ) {
    const callData = fixture.account.interface.encodeFunctionData("execute", [
      fixture.account.target,
      0,
      innerCallData,
    ]);
    const userOpHash = ethers.keccak256(ethers.toUtf8Bytes(label));
    const signature = await buildOwnerAccountSignature({
      authorizer: fixture.authorizer,
      validatorAddress: String(fixture.validator.target),
      accountAddress: String(fixture.account.target),
      ownerConfigHash: fixture.ownerConfigHash,
      userOpHash,
      chainId: fixture.chainId,
    });
    const userOp = buildUserOp({
      sender: fixture.account.target,
      callData,
      signature,
    });

    const result = await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0);
    expect(result & SIG_FAILURE_MASK).to.equal(0n);
    await fixture.account.connect(fixture.entryPoint).validateUserOp(userOp, userOpHash, 0);
    await fixture.account.connect(fixture.entryPoint).execute(fixture.account.target, 0, innerCallData);
  }

  async function grantSession(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    overrides: Partial<{
      validUntil: bigint;
      callLimit: number;
      maxBatchCalls: number;
      maxValuePerCall: number;
      maxTotalValuePerUserOp: number;
      allowBatch: boolean;
    }> = {},
  ) {
    const latest = await ethers.provider.getBlock("latest");
    const config = {
      validUntil: BigInt(latest!.timestamp) + 3600n,
      __reserved0: 0,
      __reserved1: 0,
      version: 0,
      maxBatchCalls: 0,
      maxValuePerCall: 0,
      maxTotalValuePerUserOp: 0,
      allowBatch: false,
      ...overrides,
    };
    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("grantSessionKey", [fixture.session.address, config]),
      `grant-session-v2-${Math.random()}`,
    );
    return config;
  }

  async function allowSessionTarget(
    fixture: Awaited<ReturnType<typeof deployFixture>>,
    target: string,
    selector: string,
  ) {
    await fixture.account.connect(fixture.safe).whitelistSessionTarget(target, true);
    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("setSessionTarget", [fixture.session.address, target, true]),
      `allow-target-v2-${target}`,
    );
    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("setSessionSelector", [fixture.session.address, target, selector, true]),
      `allow-selector-v2-${target}-${selector}`,
    );
  }

  it("returns packed validationData for a valid V2 owner signature", async function () {
    const fixture = await deployFixture();
    const userOpHash = ethers.keccak256(ethers.toUtf8Bytes("owner-v2-validation-window"));
    const validAfter = Math.floor(Date.now() / 1000) - 30;
    const validUntil = validAfter + 900;
    const payload = await buildOwnerPayload({
      authorizer: fixture.authorizer,
      validatorAddress: String(fixture.validator.target),
      accountAddress: String(fixture.account.target),
      ownerConfigHash: fixture.ownerConfigHash,
      userOpHash,
      chainId: fixture.chainId,
      validAfter,
      validUntil,
    });

    const validationData = await fixture.validator.validateUserOpValidationData(
      fixture.account.target,
      fixture.ownerConfigHash,
      userOpHash,
      payload,
    );

    expect(validationData).to.equal(packValidationData(false, BigInt(validUntil), BigInt(validAfter)));
  });

  it("rotates the V3 authorizer without changing the validator-backed account address", async function () {
    const [initialAuthorizer, nextAuthorizer, validatorOwner, stranger, safe, entryPoint] = await ethers.getSigners();
    const validator = await ethers.deployContract("PasskeyOwnerValidatorV3", [
      initialAuthorizer.address,
      validatorOwner.address,
    ]);
    const accountImpl = await ethers.deployContract("SmartAccountV2");
    const factory = await ethers.deployContract("AccountFactoryV2", [
      accountImpl.target,
      entryPoint.address,
      safe.address,
    ]);
    const ownerConfig = coder.encode(
      ["bytes32", "bytes32", "bytes32", "bytes32"],
      [
        ethers.keccak256(ethers.toUtf8Bytes("cred-v3")),
        ethers.keccak256(ethers.toUtf8Bytes("passkey.hazbase.com")),
        ethers.keccak256(ethers.toUtf8Bytes("pubkey-x-v3")),
        ethers.keccak256(ethers.toUtf8Bytes("pubkey-y-v3")),
      ],
    );
    const ownerConfigHash = await validator.configHash(ownerConfig);
    const predictedBefore = await factory.predictAddress(validator.target, ownerConfig, 11n);
    const userOpHash = ethers.keccak256(ethers.toUtf8Bytes("owner-v3-rotation"));
    const validAfter = Math.floor(Date.now() / 1000) - 30;
    const validUntil = validAfter + 900;
    const initialPayload = await buildOwnerPayload({
      authorizer: initialAuthorizer,
      validatorAddress: String(validator.target),
      accountAddress: predictedBefore,
      ownerConfigHash,
      userOpHash,
      chainId: BigInt((await ethers.provider.getNetwork()).chainId),
      validAfter,
      validUntil,
    });

    expect(
      await validator.validateUserOpValidationData(predictedBefore, ownerConfigHash, userOpHash, initialPayload),
    ).to.equal(packValidationData(false, BigInt(validUntil), BigInt(validAfter)));

    await expect(validator.connect(stranger).setAuthorizer(nextAuthorizer.address)).to.be.reverted;
    await expect(validator.connect(validatorOwner).setAuthorizer(nextAuthorizer.address))
      .to.emit(validator, "AuthorizerChanged")
      .withArgs(initialAuthorizer.address, nextAuthorizer.address);
    expect(await validator.authorizer()).to.equal(nextAuthorizer.address);

    const predictedAfter = await factory.predictAddress(validator.target, ownerConfig, 11n);
    expect(predictedAfter).to.equal(predictedBefore);
    expect(
      await validator.validateUserOpValidationData(predictedBefore, ownerConfigHash, userOpHash, initialPayload),
    ).to.equal(packValidationData(true, BigInt(validUntil), BigInt(validAfter)));

    const rotatedPayload = await buildOwnerPayload({
      authorizer: nextAuthorizer,
      validatorAddress: String(validator.target),
      accountAddress: predictedBefore,
      ownerConfigHash,
      userOpHash,
      chainId: BigInt((await ethers.provider.getNetwork()).chainId),
      validAfter,
      validUntil,
    });
    expect(
      await validator.validateUserOpValidationData(predictedBefore, ownerConfigHash, userOpHash, rotatedPayload),
    ).to.equal(packValidationData(false, BigInt(validUntil), BigInt(validAfter)));
  });

  it("keeps factory account creation deterministic without factory replay storage writes", async function () {
    const fixture = await deployFixture();
    const factory = await ethers.deployContract("AccountFactoryV2", [
      fixture.account.target,
      fixture.entryPoint.address,
      fixture.safe.address,
    ]);

    const predicted = await factory.predictAddress(fixture.validator.target, fixture.ownerConfig, 7n);
    await expect(factory.createAccount(fixture.validator.target, fixture.ownerConfig, 7n))
      .to.emit(factory, "AccountCreated")
      .withArgs(predicted, fixture.validator.target, fixture.ownerConfigHash, 7n);
    expect(await ethers.provider.getCode(predicted)).to.not.equal("0x");
    await expect(factory.createAccount(fixture.validator.target, fixture.ownerConfig, 7n)).to.be.revertedWith("salt-used");
  });

  it("forwards validator validationData for owner execution", async function () {
    const fixture = await deployFixture();
    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("pause"),
      "owner-v2-pause",
    );
    expect(await fixture.account.paused()).to.equal(true);
  });

  it("keeps session validation side-effect free while preserving execution allowlists", async function () {
    const fixture = await deployFixture();
    const config = await grantSession(fixture, { callLimit: 1 });
    await allowSessionTarget(
      fixture,
      String(fixture.receiver.target),
      fixture.receiver.interface.getFunction("increment").selector,
    );

    const callData = fixture.account.interface.encodeFunctionData("execute", [
      fixture.receiver.target,
      0,
      fixture.receiver.interface.encodeFunctionData("increment"),
    ]);
    const userOpHash = ethers.keccak256(ethers.toUtf8Bytes("session-v2-allowed"));
    const signature = await buildSessionAccountSignature(fixture.session, userOpHash);
    const userOp = buildUserOp({
      sender: fixture.account.target,
      callData,
      signature,
    });

    const first = await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0);
    expect(first).to.equal(packValidationData(false, config.validUntil));
    await fixture.account.connect(fixture.entryPoint).validateUserOp(userOp, userOpHash, 0);
    const afterValidation = await fixture.account.sessionConfigs(fixture.session.address);
    // (callLimit/usedCalls removed; validateUserOp stays side-effect-free)
    expect(afterValidation.validUntil).to.equal(config.validUntil);

    await fixture.account.connect(fixture.entryPoint).execute(
      fixture.receiver.target,
      0,
      fixture.receiver.interface.encodeFunctionData("increment"),
    );
    expect(await fixture.receiver.count()).to.equal(1n);

    const second = await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0);
    expect(second).to.equal(packValidationData(false, config.validUntil));
  });

  it("still rejects disallowed selectors and value violations for V2 sessions", async function () {
    const fixture = await deployFixture();
    await grantSession(fixture, { callLimit: 1, maxValuePerCall: 0, maxTotalValuePerUserOp: 0 });
    await fixture.account.connect(fixture.safe).whitelistSessionTarget(fixture.receiver.target, true);
    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("setSessionTarget", [fixture.session.address, fixture.receiver.target, true]),
      "allow-target-no-selector-v2",
    );

    const selectorMissingCall = fixture.account.interface.encodeFunctionData("execute", [
      fixture.receiver.target,
      0,
      fixture.receiver.interface.encodeFunctionData("increment"),
    ]);
    let userOpHash = ethers.keccak256(ethers.toUtf8Bytes("session-v2-selector-missing"));
    let userOp = buildUserOp({
      sender: fixture.account.target,
      callData: selectorMissingCall,
      signature: await buildSessionAccountSignature(fixture.session, userOpHash),
    });
    expect(await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0)).to.equal(1n);

    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("setSessionSelector", [
        fixture.session.address,
        fixture.receiver.target,
        fixture.receiver.interface.getFunction("increment").selector,
        true,
      ]),
      "allow-selector-now-v2",
    );

    const tooMuchValueCall = fixture.account.interface.encodeFunctionData("execute", [
      fixture.receiver.target,
      1,
      fixture.receiver.interface.encodeFunctionData("increment"),
    ]);
    userOpHash = ethers.keccak256(ethers.toUtf8Bytes("session-v2-value-too-high"));
    userOp = buildUserOp({
      sender: fixture.account.target,
      callData: tooMuchValueCall,
      signature: await buildSessionAccountSignature(fixture.session, userOpHash),
    });
    expect(await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0)).to.equal(1n);
  });

  it("uses the validation window for expiry and explicit revoke for denial", async function () {
    const fixture = await deployFixture();
    const latest = await ethers.provider.getBlock("latest");
    const validUntil = BigInt(latest!.timestamp) + 120n;
    await grantSession(fixture, { validUntil, callLimit: 1 });
    await allowSessionTarget(
      fixture,
      String(fixture.receiver.target),
      fixture.receiver.interface.getFunction("increment").selector,
    );

    const callData = fixture.account.interface.encodeFunctionData("execute", [
      fixture.receiver.target,
      0,
      fixture.receiver.interface.encodeFunctionData("increment"),
    ]);
    const userOpHash = ethers.keccak256(ethers.toUtf8Bytes("session-v2-expired-window"));
    const userOp = buildUserOp({
      sender: fixture.account.target,
      callData,
      signature: await buildSessionAccountSignature(fixture.session, userOpHash),
    });

    await ethers.provider.send("evm_increaseTime", [180]);
    await ethers.provider.send("evm_mine", []);

    const expired = await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0);
    expect(expired).to.equal(packValidationData(false, validUntil));

    await execAsOwner(
      fixture,
      fixture.account.interface.encodeFunctionData("revokeSessionKey", [fixture.session.address]),
      "revoke-session-v2",
    );
    expect(await fixture.account.connect(fixture.entryPoint).validateUserOp.staticCall(userOp, userOpHash, 0)).to.equal(1n);
  });
});

import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

const assignmentTypes = {
  BeneficiaryAssignment: [
    { name: "escrowId", type: "bytes32" },
    { name: "beneficiary", type: "address" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

async function deployFixture() {
  const [admin, creator, contributorA, contributorB, beneficiary, authorizer, outsider] =
    await ethers.getSigners();
  const token = await ethers.deployContract("MockERC20", ["Test Token", "TEST"]);
  const implementation = await ethers.deployContract("PooledTokenEscrow");
  const cloneFactory = await ethers.deployContract("MockCloneFactory");
  const escrowInterface = (await ethers.getContractFactory("PooledTokenEscrow")).interface;
  const initData = escrowInterface.encodeFunctionData("initialize", [admin.address]);
  const escrowAddress = await cloneFactory.deploy.staticCall(await implementation.getAddress(), initData);
  await cloneFactory.deploy(await implementation.getAddress(), initData);
  const escrow = await ethers.getContractAt("PooledTokenEscrow", escrowAddress);
  return {
    admin,
    creator,
    contributorA,
    contributorB,
    beneficiary,
    authorizer,
    outsider,
    token,
    escrow,
    implementation,
    cloneFactory,
  };
}

async function approve(token: any, owner: any, escrow: any, amount: bigint) {
  await token.mint(owner.address, amount);
  await token.connect(owner).approve(await escrow.getAddress(), amount);
}

describe("PooledTokenEscrow", function () {
  it("pools contributions and releases the complete balance to a fixed beneficiary", async function () {
    const { creator, contributorA, contributorB, beneficiary, token, escrow } = await deployFixture();
    const escrowId = ethers.id("fixed-beneficiary");
    const tokenAddress = await token.getAddress();

    await escrow
      .connect(creator)
      .createEscrow(escrowId, tokenAddress, beneficiary.address, ethers.ZeroAddress, 0, ethers.ZeroHash);
    await approve(token, contributorA, escrow, 400n);
    await approve(token, contributorB, escrow, 600n);
    await escrow.connect(contributorA).deposit(escrowId, ethers.id("a-1"), 400n);
    await escrow.connect(contributorB).deposit(escrowId, ethers.id("b-1"), 600n);

    expect(await escrow.contributionOf(escrowId, contributorA.address)).to.equal(400n);
    expect(await escrow.lockedBalanceOf(tokenAddress)).to.equal(1_000n);
    await expect(escrow.connect(beneficiary).claim(escrowId))
      .to.emit(escrow, "EscrowReleased")
      .withArgs(escrowId, beneficiary.address, 1_000n);

    expect(await token.balanceOf(beneficiary.address)).to.equal(1_000n);
    expect(await escrow.lockedBalanceOf(tokenAddress)).to.equal(0n);
    expect((await escrow.getEscrow(escrowId)).status).to.equal(2n);
    await expect(escrow.connect(beneficiary).claim(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "EscrowNotOpen",
    );
  });

  it("assigns an initially unknown beneficiary with a domain-separated authorization", async function () {
    const { creator, beneficiary, authorizer, outsider, token, escrow } = await deployFixture();
    const escrowId = ethers.id("assign-later");
    const latest = await time.latest();
    const deadline = BigInt(latest + 3_600);
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        ethers.ZeroAddress,
        authorizer.address,
        0,
        ethers.id("private-metadata"),
      );

    const network = await ethers.provider.getNetwork();
    const domain = {
      name: "PooledTokenEscrow",
      version: "1",
      chainId: network.chainId,
      verifyingContract: await escrow.getAddress(),
    };
    const authorization = { escrowId, beneficiary: beneficiary.address, nonce: 0n, deadline };
    const badSignature = await outsider.signTypedData(domain, assignmentTypes, authorization);
    await expect(
      escrow.assignBeneficiary(escrowId, beneficiary.address, 0, deadline, badSignature),
    ).to.be.revertedWithCustomError(escrow, "InvalidAuthorization");

    const signature = await authorizer.signTypedData(domain, assignmentTypes, authorization);
    await expect(escrow.assignBeneficiary(escrowId, beneficiary.address, 0, deadline, signature))
      .to.emit(escrow, "BeneficiaryAssigned")
      .withArgs(escrowId, beneficiary.address, authorizer.address, 0);

    expect((await escrow.getEscrow(escrowId)).beneficiary).to.equal(beneficiary.address);
    await expect(
      escrow.assignBeneficiary(escrowId, outsider.address, 0, deadline, signature),
    ).to.be.revertedWithCustomError(escrow, "BeneficiaryAlreadyAssigned");
  });

  it("supports an ERC-1271 contract authorizer", async function () {
    const { creator, beneficiary, authorizer, token, escrow } = await deployFixture();
    const contractAuthorizer = await ethers.deployContract("MockERC1271Authorizer", [authorizer.address]);
    const escrowId = ethers.id("contract-authorizer");
    const deadline = BigInt((await time.latest()) + 3_600);
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        ethers.ZeroAddress,
        await contractAuthorizer.getAddress(),
        0,
        ethers.ZeroHash,
      );

    const network = await ethers.provider.getNetwork();
    const domain = {
      name: "PooledTokenEscrow",
      version: "1",
      chainId: network.chainId,
      verifyingContract: await escrow.getAddress(),
    };
    const assignment = { escrowId, beneficiary: beneficiary.address, nonce: 0n, deadline };
    const signature = await authorizer.signTypedData(domain, assignmentTypes, assignment);
    await escrow.assignBeneficiary(escrowId, beneficiary.address, 0, deadline, signature);
    expect((await escrow.getEscrow(escrowId)).beneficiary).to.equal(beneficiary.address);
  });

  it("rejects beneficiary authorizations replayed against another escrow instance", async function () {
    const {
      admin,
      creator,
      beneficiary,
      authorizer,
      token,
      escrow,
      implementation,
      cloneFactory,
    } = await deployFixture();
    const escrowId = ethers.id("cross-instance-replay");
    const escrowInterface = (await ethers.getContractFactory("PooledTokenEscrow")).interface;
    const initData = escrowInterface.encodeFunctionData("initialize", [admin.address]);
    const secondAddress = await cloneFactory.deploy.staticCall(
      await implementation.getAddress(),
      initData,
    );
    await cloneFactory.deploy(await implementation.getAddress(), initData);
    const secondEscrow = await ethers.getContractAt("PooledTokenEscrow", secondAddress);
    for (const instance of [escrow, secondEscrow]) {
      await instance
        .connect(creator)
        .createEscrow(
          escrowId,
          await token.getAddress(),
          ethers.ZeroAddress,
          authorizer.address,
          0,
          ethers.ZeroHash,
        );
    }

    const deadline = BigInt((await time.latest()) + 3_600);
    const network = await ethers.provider.getNetwork();
    const signature = await authorizer.signTypedData(
      {
        name: "PooledTokenEscrow",
        version: "1",
        chainId: network.chainId,
        verifyingContract: await escrow.getAddress(),
      },
      assignmentTypes,
      { escrowId, beneficiary: beneficiary.address, nonce: 0n, deadline },
    );

    await expect(
      secondEscrow.assignBeneficiary(
        escrowId,
        beneficiary.address,
        0n,
        deadline,
        signature,
      ),
    ).to.be.revertedWithCustomError(secondEscrow, "InvalidAuthorization");
  });

  it("prevents duplicate contribution ids and credits the amount actually received", async function () {
    const { creator, contributorA, beneficiary, escrow } = await deployFixture();
    const feeToken = await ethers.deployContract("MockFeeOnTransferERC20", [500]);
    const escrowId = ethers.id("fee-token");
    const contributionId = ethers.id("retry-safe");
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await feeToken.getAddress(),
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );
    await approve(feeToken, contributorA, escrow, 1_000n);

    await expect(escrow.connect(contributorA).deposit(escrowId, contributionId, 1_000n))
      .to.emit(escrow, "ContributionDeposited")
      .withArgs(escrowId, contributionId, contributorA.address, 1_000n, 950n);
    expect(await escrow.contributionAmount(escrowId, contributionId)).to.equal(950n);
    expect((await escrow.getEscrow(escrowId)).totalDeposited).to.equal(950n);

    await expect(
      escrow.connect(contributorA).deposit(escrowId, contributionId, 1n),
    ).to.be.revertedWithCustomError(escrow, "ContributionAlreadyExists");
  });

  it("lets contributors independently refund after a finite escrow expires", async function () {
    const { creator, contributorA, contributorB, authorizer, token, escrow } = await deployFixture();
    const escrowId = ethers.id("expiring");
    const expiry = (await time.latest()) + 100;
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        ethers.ZeroAddress,
        authorizer.address,
        expiry,
        ethers.ZeroHash,
      );
    await approve(token, contributorA, escrow, 300n);
    await approve(token, contributorB, escrow, 700n);
    await escrow.connect(contributorA).deposit(escrowId, ethers.id("expiry-a"), 300n);
    await escrow.connect(contributorB).deposit(escrowId, ethers.id("expiry-b"), 700n);

    await expect(escrow.enableRefunds(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "EscrowNotExpired",
    );
    await time.increaseTo(expiry);
    await expect(escrow.connect(contributorA).deposit(escrowId, ethers.id("late"), 1n))
      .to.be.revertedWithCustomError(escrow, "EscrowExpired");
    await escrow.connect(contributorB).enableRefunds(escrowId);

    await expect(escrow.connect(contributorA).refund(escrowId))
      .to.emit(escrow, "ContributionRefunded")
      .withArgs(escrowId, contributorA.address, 300n);
    expect((await escrow.getEscrow(escrowId)).status).to.equal(3n);
    await escrow.connect(contributorB).refund(escrowId);
    expect((await escrow.getEscrow(escrowId)).status).to.equal(4n);
    expect(await token.balanceOf(contributorA.address)).to.equal(300n);
    expect(await token.balanceOf(contributorB.address)).to.equal(700n);
  });

  it("allows creator cancellation but never transfers contributor funds to the creator", async function () {
    const { creator, contributorA, beneficiary, token, escrow } = await deployFixture();
    const escrowId = ethers.id("cancelled");
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );
    await approve(token, contributorA, escrow, 500n);
    await escrow.connect(contributorA).deposit(escrowId, ethers.id("cancel-a"), 500n);
    await escrow.connect(creator).cancelEscrow(escrowId);

    expect(await token.balanceOf(creator.address)).to.equal(0n);
    expect(await escrow.refundableOf(escrowId, contributorA.address)).to.equal(500n);
    await escrow.connect(contributorA).refund(escrowId);
    expect(await token.balanceOf(contributorA.address)).to.equal(500n);
  });

  it("keeps aggregate token liabilities solvent across independent escrows", async function () {
    const { creator, contributorA, contributorB, beneficiary, authorizer, token, escrow } =
      await deployFixture();
    const claimEscrowId = ethers.id("aggregate-claim");
    const refundEscrowId = ethers.id("aggregate-refund");
    const tokenAddress = await token.getAddress();
    await escrow
      .connect(creator)
      .createEscrow(
        claimEscrowId,
        tokenAddress,
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );
    await escrow
      .connect(creator)
      .createEscrow(
        refundEscrowId,
        tokenAddress,
        ethers.ZeroAddress,
        authorizer.address,
        0,
        ethers.ZeroHash,
      );
    await approve(token, contributorA, escrow, 100n);
    await approve(token, contributorB, escrow, 200n);
    await escrow.connect(contributorA).deposit(claimEscrowId, ethers.id("aggregate-a"), 100n);
    await escrow.connect(contributorB).deposit(refundEscrowId, ethers.id("aggregate-b"), 200n);
    expect(await escrow.lockedBalanceOf(tokenAddress)).to.equal(300n);

    await escrow.connect(beneficiary).claim(claimEscrowId);
    expect(await escrow.lockedBalanceOf(tokenAddress)).to.equal(200n);
    await escrow.connect(creator).cancelEscrow(refundEscrowId);
    await escrow.connect(contributorB).refund(refundEscrowId);
    expect(await escrow.lockedBalanceOf(tokenAddress)).to.equal(0n);
    expect(await token.balanceOf(await escrow.getAddress())).to.equal(0n);
  });

  it("enforces pause controls and leaves indefinite escrows without automatic expiry", async function () {
    const { admin, creator, contributorA, beneficiary, outsider, token, escrow } = await deployFixture();
    const escrowId = ethers.id("indefinite");
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );
    await expect(escrow.enableRefunds(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "EscrowNotExpired",
    );
    await approve(token, contributorA, escrow, 10n);
    await expect(escrow.connect(outsider).pause())
      .to.be.revertedWithCustomError(escrow, "AccessControlUnauthorizedAccount")
      .withArgs(outsider.address, await escrow.PAUSER_ROLE());
    await escrow.connect(admin).pause();
    await expect(
      escrow.connect(contributorA).deposit(escrowId, ethers.id("paused"), 10n),
    ).to.be.revertedWithCustomError(escrow, "EnforcedPause");
    await escrow.connect(admin).unpause();
    await escrow.connect(contributorA).deposit(escrowId, ethers.id("unpaused"), 10n);
    expect((await escrow.getEscrow(escrowId)).totalDeposited).to.equal(10n);
  });

  it("rejects invalid initialization and escrow definitions", async function () {
    const { admin, creator, beneficiary, authorizer, outsider, token, escrow, implementation } =
      await deployFixture();
    const tokenAddress = await token.getAddress();
    const escrowId = ethers.id("definition-validation");

    await expect(implementation.initialize(admin.address)).to.be.revertedWithCustomError(
      implementation,
      "InvalidInitialization",
    );
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          ethers.ZeroHash,
          tokenAddress,
          beneficiary.address,
          ethers.ZeroAddress,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "InvalidEscrowId");
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          ethers.ZeroAddress,
          beneficiary.address,
          ethers.ZeroAddress,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "ZeroAddress");
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          outsider.address,
          beneficiary.address,
          ethers.ZeroAddress,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "ZeroAddress");
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          tokenAddress,
          ethers.ZeroAddress,
          ethers.ZeroAddress,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "InvalidBeneficiaryConfiguration");
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          tokenAddress,
          beneficiary.address,
          authorizer.address,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "InvalidBeneficiaryConfiguration");
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          tokenAddress,
          beneficiary.address,
          ethers.ZeroAddress,
          await time.latest(),
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "InvalidExpiry");

    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        tokenAddress,
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );
    await expect(
      escrow
        .connect(creator)
        .createEscrow(
          escrowId,
          tokenAddress,
          beneficiary.address,
          ethers.ZeroAddress,
          0,
          ethers.ZeroHash,
        ),
    ).to.be.revertedWithCustomError(escrow, "EscrowAlreadyExists");
  });

  it("rejects invalid deposits, beneficiary assignments, and claims", async function () {
    const { creator, contributorA, beneficiary, authorizer, outsider, token, escrow } =
      await deployFixture();
    const escrowId = ethers.id("operation-validation");
    const tokenAddress = await token.getAddress();
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        tokenAddress,
        ethers.ZeroAddress,
        authorizer.address,
        0,
        ethers.ZeroHash,
      );

    await expect(
      escrow.connect(contributorA).deposit(ethers.id("missing"), ethers.id("missing-deposit"), 1n),
    ).to.be.revertedWithCustomError(escrow, "EscrowNotFound");
    await expect(
      escrow.connect(contributorA).deposit(escrowId, ethers.ZeroHash, 1n),
    ).to.be.revertedWithCustomError(escrow, "InvalidContributionId");
    await expect(
      escrow.connect(contributorA).deposit(escrowId, ethers.id("zero-amount"), 0n),
    ).to.be.revertedWithCustomError(escrow, "InvalidAmount");
    await expect(escrow.connect(beneficiary).claim(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "BeneficiaryNotAssigned",
    );
    await expect(
      escrow.assignBeneficiary(escrowId, ethers.ZeroAddress, 0n, 2_000_000_000n, "0x"),
    ).to.be.revertedWithCustomError(escrow, "ZeroAddress");
    await expect(
      escrow.assignBeneficiary(escrowId, beneficiary.address, 1n, 2_000_000_000n, "0x"),
    ).to.be.revertedWithCustomError(escrow, "InvalidAuthorizationNonce");
    await expect(
      escrow.assignBeneficiary(
        escrowId,
        beneficiary.address,
        0n,
        BigInt((await time.latest()) - 1),
        "0x",
      ),
    ).to.be.revertedWithCustomError(escrow, "AuthorizationExpired");

    const deadline = BigInt((await time.latest()) + 3_600);
    const network = await ethers.provider.getNetwork();
    const signature = await authorizer.signTypedData(
      {
        name: "PooledTokenEscrow",
        version: "1",
        chainId: network.chainId,
        verifyingContract: await escrow.getAddress(),
      },
      assignmentTypes,
      { escrowId, beneficiary: beneficiary.address, nonce: 0n, deadline },
    );
    await escrow.assignBeneficiary(escrowId, beneficiary.address, 0n, deadline, signature);
    await expect(escrow.connect(outsider).claim(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "NotBeneficiary",
    );
    await expect(escrow.connect(beneficiary).claim(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "NothingToClaim",
    );
  });

  it("enforces cancellation and refund ownership, including empty pools", async function () {
    const { creator, contributorA, outsider, beneficiary, token, escrow } = await deployFixture();
    const escrowId = ethers.id("refund-validation");
    await escrow
      .connect(creator)
      .createEscrow(
        escrowId,
        await token.getAddress(),
        beneficiary.address,
        ethers.ZeroAddress,
        0,
        ethers.ZeroHash,
      );

    await expect(escrow.connect(outsider).cancelEscrow(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "NotCreator",
    );
    await expect(escrow.connect(contributorA).refund(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "RefundsNotEnabled",
    );
    await expect(escrow.connect(creator).cancelEscrow(escrowId))
      .to.emit(escrow, "RefundsEnabled")
      .withArgs(escrowId, creator.address, 0n)
      .and.to.emit(escrow, "EscrowClosed")
      .withArgs(escrowId);
    expect((await escrow.getEscrow(escrowId)).status).to.equal(4n);
    await expect(escrow.connect(contributorA).refund(escrowId)).to.be.revertedWithCustomError(
      escrow,
      "RefundsNotEnabled",
    );

    expect(await escrow.contractType()).to.equal("PooledTokenEscrow");
    expect(await escrow.contractVersion()).to.equal("1");
    expect(await escrow.refundedOf(escrowId, contributorA.address)).to.equal(0n);
    expect(await escrow.isContributionIdUsed(escrowId, ethers.id("unused"))).to.equal(false);
  });
});

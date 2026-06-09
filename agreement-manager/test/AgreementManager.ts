import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitAgreementLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_AGREEMENT_LEDGER_OUTPUT === '1') {
    console.log(`RWA_AGREEMENT_LEDGER::${JSON.stringify(entry)}`);
  }
}

const offerTypes = {
  Offer: [
    { name: 'issuer', type: 'address' },
    { name: 'investor', type: 'address' },
    { name: 'tokenAddress', type: 'address' },
    { name: 'partition', type: 'bytes32' },
    { name: 'tokenId', type: 'uint256' },
    { name: 'amount', type: 'uint256' },
    { name: 'classId', type: 'uint256' },
    { name: 'nonceId', type: 'uint256' },
    { name: 'documentHash', type: 'bytes32' },
    { name: 'documentURI', type: 'string' },
    { name: 'expiry', type: 'uint256' },
    { name: 'nonce', type: 'uint256' },
  ],
};

async function deployAgreementManager(adminAddress: string) {
  const factory = await ethers.getContractFactory('AgreementManager');
  const manager = await upgrades.deployProxy(factory, [adminAddress, []], {
    kind: 'uups',
    initializer: 'initialize',
  });
  await manager.waitForDeployment();
  return manager;
}

async function buildOfferFixture(manager: any, overrides: Partial<Record<string, unknown>> = {}) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const latest = await ethers.provider.getBlock('latest');
  return {
    domain: {
      name: 'AgreementManager',
      version: '1',
      chainId,
      verifyingContract: await manager.getAddress(),
    },
    offer: {
      issuer: overrides.issuer,
      investor: overrides.investor,
      tokenAddress: overrides.tokenAddress,
      partition: overrides.partition ?? ethers.ZeroHash,
      tokenId: overrides.tokenId ?? 0n,
      amount: overrides.amount ?? 0n,
      classId: overrides.classId ?? 0n,
      nonceId: overrides.nonceId ?? 0n,
      documentHash: overrides.documentHash ?? ethers.keccak256(ethers.toUtf8Bytes('logistics-facility-agreement')),
      documentURI: overrides.documentURI ?? 'ipfs://hazbase/rwa/agreement/logistics-2026-01',
      expiry: overrides.expiry ?? BigInt((latest?.timestamp ?? 0) + 3600),
      nonce: overrides.nonce ?? 0n,
    },
  };
}

function computeOfferId(offer: {
  issuer: string;
  investor: string;
  tokenAddress: string;
  partition: string;
  tokenId: bigint;
  amount: bigint;
  classId: bigint;
  nonceId: bigint;
  documentHash: string;
  documentURI: string;
  expiry: bigint;
  nonce: bigint;
}) {
  const coder = ethers.AbiCoder.defaultAbiCoder();
  return ethers.keccak256(
    coder.encode(
      [
        'bytes1', 'address',
        'bytes1', 'address',
        'bytes1', 'address',
        'bytes32', 'uint256', 'uint256', 'uint256',
        'uint256', 'bytes32', 'bytes32', 'uint256', 'uint256',
      ],
      [
        '0x01', offer.issuer,
        '0x02', offer.investor,
        '0x03', offer.tokenAddress,
        offer.partition,
        offer.tokenId,
        offer.amount,
        offer.classId,
        offer.nonceId,
        offer.documentHash,
        ethers.keccak256(ethers.toUtf8Bytes(offer.documentURI)),
        offer.expiry,
        offer.nonce,
      ],
    ),
  );
}

describe('AgreementManager internal coverage', function () {
  it('creates and settles a delegated ERC20 offer via the designated market', async function () {
    const [admin, issuer, investor, delegatedMarket] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const manager = await deployAgreementManager(admin.address);

    await token.mint(issuer.address, 1_000n);
    await token.connect(issuer).approve(await manager.getAddress(), 1_000n);

    const { domain, offer } = await buildOfferFixture(manager, {
      issuer: issuer.address,
      investor: investor.address,
      tokenAddress: await token.getAddress(),
      amount: 250n,
      nonce: 1n,
    });

    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer as any);

    await expect(
      manager.connect(issuer).offer(
        offer.investor,
        offer.tokenAddress,
        offer.partition,
        offer.tokenId,
        offer.amount,
        offer.classId,
        offer.nonceId,
        offer.documentHash,
        offer.documentURI,
        offer.expiry,
        offer.nonce,
        issuerSig,
        delegatedMarket.address,
      )
    ).to.emit(manager, 'OfferCreated').withArgs(offerId, issuer.address, investor.address);

    expect(await token.balanceOf(await manager.getAddress())).to.equal(250n);
    expect((await manager.getOffer(offerId)).status).to.equal(1n);

    const investorSig = await investor.signTypedData(domain, offerTypes, offer);
    await expect(manager.connect(delegatedMarket).acceptOffer(offerId, investorSig))
      .to.emit(manager, 'OfferSettled');

    expect(await token.balanceOf(investor.address)).to.equal(250n);
    expect(await token.balanceOf(await manager.getAddress())).to.equal(0n);
    expect(await manager.isSettled(offerId)).to.equal(true);
    expect((await manager.getOffer(offerId)).status).to.equal(0n);

    emitAgreementLedger({
      scenario: 'AGMT-CS-01',
      source: 'agreement-manager',
      ledger: {
        manager_escrow_balance: '0',
        investor_received: '250',
        issuer_balance_after_escrow: '750',
        delegated_market: delegatedMarket.address,
        offer_status_after_settle: 'cleaned',
      },
      checks: {
        offer_created: true,
        delegated_accept: true,
        settlement_complete: true,
      },
    });
  });

  it('rejects invalid delegated settlement attempts and lets the issuer cancel to unwind escrow', async function () {
    const [admin, issuer, investor, delegatedMarket, outsider] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const manager = await deployAgreementManager(admin.address);

    await token.mint(issuer.address, 500n);
    await token.connect(issuer).approve(await manager.getAddress(), 500n);

    const { domain, offer } = await buildOfferFixture(manager, {
      issuer: issuer.address,
      investor: investor.address,
      tokenAddress: await token.getAddress(),
      amount: 100n,
      nonce: 2n,
    });
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer as any);

    await manager.connect(issuer).offer(
      offer.investor,
      offer.tokenAddress,
      offer.partition,
      offer.tokenId,
      offer.amount,
      offer.classId,
      offer.nonceId,
      offer.documentHash,
      offer.documentURI,
      offer.expiry,
      offer.nonce,
      issuerSig,
      delegatedMarket.address,
    );

    const outsiderSig = await outsider.signTypedData(domain, offerTypes, offer);

    await expect(manager.connect(investor).acceptOffer(offerId, outsiderSig)).to.be.revertedWith('delegated:auth');
    await expect(manager.connect(delegatedMarket).acceptOffer(offerId, outsiderSig)).to.be.revertedWith('bad sig');

    await expect(manager.connect(issuer).cancelOffer(offerId)).to.emit(manager, 'OfferCancelled');
    expect(await token.balanceOf(issuer.address)).to.equal(500n);
    expect(await token.balanceOf(await manager.getAddress())).to.equal(0n);
    expect((await manager.getOffer(offerId)).status).to.equal(0n);

    emitAgreementLedger({
      scenario: 'AGMT-CS-02',
      source: 'agreement-manager',
      ledger: {
        manager_escrow_balance: '0',
        issuer_balance_restored: '500',
        invalid_delegate_attempts_blocked: true,
        offer_status_after_cancel: 'cleaned',
      },
      checks: {
        delegated_auth_enforced: true,
        investor_sig_enforced: true,
        cancel_unwinds_escrow: true,
      },
    });
  });

  it('supports investor reject, dispute lifecycle, and pause guards', async function () {
    const [admin, issuer, investor, stranger] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const manager = await deployAgreementManager(admin.address);
    await manager.grantRole(await manager.GUARDIAN_ROLE(), admin.address);

    await token.mint(issuer.address, 400n);
    await token.connect(issuer).approve(await manager.getAddress(), 400n);

    const { domain, offer } = await buildOfferFixture(manager, {
      issuer: issuer.address,
      investor: investor.address,
      tokenAddress: await token.getAddress(),
      amount: 80n,
      nonce: 3n,
    });
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer as any);

    await manager.connect(issuer).offer(
      offer.investor,
      offer.tokenAddress,
      offer.partition,
      offer.tokenId,
      offer.amount,
      offer.classId,
      offer.nonceId,
      offer.documentHash,
      offer.documentURI,
      offer.expiry,
      offer.nonce,
      issuerSig,
      ethers.ZeroAddress,
    );

    await expect(manager.connect(stranger).rejectOffer(offerId)).to.be.revertedWith('Wrong investor');
    await expect(manager.connect(investor).rejectOffer(offerId)).to.emit(manager, 'OfferRejected');
    expect(await token.balanceOf(issuer.address)).to.equal(400n);
    expect(await token.balanceOf(await manager.getAddress())).to.equal(0n);

    await manager.connect(admin).pause();
    await expect(
      manager.connect(issuer).offer(
        offer.investor,
        offer.tokenAddress,
        offer.partition,
        offer.tokenId,
        offer.amount,
        offer.classId,
        offer.nonceId,
        offer.documentHash,
        offer.documentURI,
        offer.expiry + 1n,
        4n,
        issuerSig,
        ethers.ZeroAddress,
      )
    ).to.be.reverted;
    await manager.connect(admin).unpause();

    const disputeEvidence = 'ipfs://hazbase/disputes/logistics-2026-01';
    const tx = await manager.connect(investor).raiseDispute(ethers.ZeroHash, disputeEvidence);
    const receipt = await tx.wait();
    const block = await ethers.provider.getBlock(receipt!.blockNumber);
    const disputeId = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ['address', 'uint256', 'bytes32', 'string'],
        [investor.address, BigInt(block!.timestamp), ethers.ZeroHash, disputeEvidence],
      ),
    );

    expect((await manager.getDispute(disputeId)).status).to.equal(1n);
    await expect(manager.connect(admin).setDisputeStatus(disputeId, 3)).to.emit(manager, 'DisputeStatusChanged');
    expect((await manager.getDispute(disputeId)).status).to.equal(3n);

    emitAgreementLedger({
      scenario: 'AGMT-CS-03',
      source: 'agreement-manager',
      ledger: {
        manager_escrow_balance: '0',
        issuer_balance_after_reject: '400',
        dispute_status: 'resolved',
        paused_offer_blocked: true,
      },
      checks: {
        wrong_investor_blocked: true,
        reject_returns_escrow: true,
        dispute_lifecycle: true,
        pause_guard: true,
      },
    });
  });
});

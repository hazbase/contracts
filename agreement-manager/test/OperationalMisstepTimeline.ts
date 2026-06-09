import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitMisstepLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_MISSTEP_LEDGER_OUTPUT === '1') {
    console.log(`RWA_MISSTEP_LEDGER::${JSON.stringify(entry)}`);
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
      documentHash: overrides.documentHash ?? ethers.keccak256(ethers.toUtf8Bytes('wrong-first-action-offer')),
      documentURI: overrides.documentURI ?? 'ipfs://hazbase/ops/wrong-first-action',
      expiry: overrides.expiry ?? BigInt((latest?.timestamp ?? 0) + 3600),
      nonce: overrides.nonce ?? 0n,
    },
  };
}

describe('AgreementManager operator-misstep timeline coverage', function () {
  it('emits misstep ledger for MSTEP-02 pause-first action that blocks cleanup until unpause and cancel', async function () {
    const [admin, issuer, investor, delegatedMarket] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const manager = await deployAgreementManager(admin.address);

    await token.mint(issuer.address, 500n);
    await token.connect(issuer).approve(await manager.getAddress(), 500n);

    const { domain, offer } = await buildOfferFixture(manager, {
      issuer: issuer.address,
      investor: investor.address,
      tokenAddress: await token.getAddress(),
      amount: 100n,
      nonce: 91n,
    });
    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const investorSig = await investor.signTypedData(domain, offerTypes, offer);
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

    expect(await token.balanceOf(await manager.getAddress())).to.equal(100n);

    await manager.pause();
    await expect(manager.connect(delegatedMarket).acceptOffer(offerId, investorSig)).to.be.reverted;
    await expect(manager.connect(issuer).cancelOffer(offerId)).to.be.reverted;

    await manager.unpause();
    await expect(manager.connect(issuer).cancelOffer(offerId)).to.emit(manager, 'OfferCancelled');

    expect(await token.balanceOf(issuer.address)).to.equal(500n);
    expect(await token.balanceOf(await manager.getAddress())).to.equal(0n);

    emitMisstepLedger({
      scenario: 'MSTEP-02',
      source: 'agreement-manager',
      ledger: {
        wrong_first_action_state: 'paused_before_cancel',
        escrow_locked_while_paused: 100,
        escrow_returned_after_recovery: 100,
      },
      checks: {
        accept_blocked_while_paused: true,
        cancel_blocked_while_paused: true,
        unpause_then_cancel_recovered_escrow: true,
      },
    });
  });
});

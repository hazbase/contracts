import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitDelayLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_DELAY_LEDGER_OUTPUT === '1') {
    console.log(`RWA_DELAY_LEDGER::${JSON.stringify(entry)}`);
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

async function deployAgreementManager(adminAddress: string) {
  const factory = await ethers.getContractFactory('AgreementManager');
  const manager = await upgrades.deployProxy(factory, [adminAddress, []], {
    kind: 'uups',
    initializer: 'initialize',
  });
  await manager.waitForDeployment();
  return manager;
}

async function buildOffer(manager: any, issuer: string, investor: string, tokenAddress: string, amount: bigint, nonce: bigint, documentURI: string) {
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const latest = await ethers.provider.getBlock('latest');
  const offer = {
    issuer,
    investor,
    tokenAddress,
    partition: ethers.ZeroHash,
    tokenId: 0n,
    amount,
    classId: 0n,
    nonceId: 0n,
    documentHash: ethers.keccak256(ethers.toUtf8Bytes(documentURI)),
    documentURI,
    expiry: BigInt((latest?.timestamp ?? 0) + 3600),
    nonce,
  };
  return {
    domain: {
      name: 'AgreementManager',
      version: '1',
      chainId,
      verifyingContract: await manager.getAddress(),
    },
    offer,
    offerId: computeOfferId(offer),
  };
}

describe('AgreementManager delayed-response coverage', function () {
  it('emits delay ledger for DELAY-02 delegated OTC hazard window before cancel and pause', async function () {
    const [admin, issuer, investor, delegatedMarket] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
    const manager = await deployAgreementManager(admin.address);

    await token.mint(issuer.address, 500n);
    await token.connect(issuer).approve(await manager.getAddress(), 500n);

    const offerA = await buildOffer(manager, issuer.address, investor.address, await token.getAddress(), 100n, 1n, 'ipfs://hazbase/delay/offer-a');
    const offerASig = await issuer.signTypedData(offerA.domain, offerTypes, offerA.offer);
    await manager.connect(issuer).offer(
      offerA.offer.investor,
      offerA.offer.tokenAddress,
      offerA.offer.partition,
      offerA.offer.tokenId,
      offerA.offer.amount,
      offerA.offer.classId,
      offerA.offer.nonceId,
      offerA.offer.documentHash,
      offerA.offer.documentURI,
      offerA.offer.expiry,
      offerA.offer.nonce,
      offerASig,
      delegatedMarket.address,
    );
    const investorSigA = await investor.signTypedData(offerA.domain, offerTypes, offerA.offer);
    await expect(manager.connect(delegatedMarket).acceptOffer(offerA.offerId, investorSigA)).to.emit(manager, 'OfferSettled');
    expect(await token.balanceOf(investor.address)).to.equal(100n);

    const offerB = await buildOffer(manager, issuer.address, investor.address, await token.getAddress(), 120n, 2n, 'ipfs://hazbase/delay/offer-b');
    const offerBSig = await issuer.signTypedData(offerB.domain, offerTypes, offerB.offer);
    await manager.connect(issuer).offer(
      offerB.offer.investor,
      offerB.offer.tokenAddress,
      offerB.offer.partition,
      offerB.offer.tokenId,
      offerB.offer.amount,
      offerB.offer.classId,
      offerB.offer.nonceId,
      offerB.offer.documentHash,
      offerB.offer.documentURI,
      offerB.offer.expiry,
      offerB.offer.nonce,
      offerBSig,
      delegatedMarket.address,
    );

    await expect(manager.connect(issuer).cancelOffer(offerB.offerId)).to.emit(manager, 'OfferCancelled');
    await manager.pause();
    const investorSigB = await investor.signTypedData(offerB.domain, offerTypes, offerB.offer);
    await expect(manager.connect(delegatedMarket).acceptOffer(offerB.offerId, investorSigB)).to.be.reverted;

    emitDelayLedger({
      scenario: 'DELAY-02',
      source: 'agreement-manager',
      ledger: {
        pre_cleanup_offer_state: 'accepted_before_cleanup',
        post_cleanup_offer_state: 'cancelled_then_paused',
      },
      checks: {
        pre_cleanup_settlement_possible: true,
        post_cleanup_settlement_blocked: true,
      },
    });
  });
});

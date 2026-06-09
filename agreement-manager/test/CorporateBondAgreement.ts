import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitCorporateBondLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CORP_BOND_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CORP_BOND_LEDGER::${JSON.stringify(entry)}`);
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

describe('AgreementManager corporate bond OTC coverage', function () {
  it('emits corporate bond ledger for CBOND-CS-03 delegated OTC transfer settlement', async function () {
    const [admin, issuer, investor, dealer] = await ethers.getSigners();
    const token = await ethers.deployContract('MockERC20', ['Corporate Bond Unit', 'CBND']);
    const manager = await deployAgreementManager(admin.address);

    await token.mint(issuer.address, 1_000n);
    await token.connect(issuer).approve(await manager.getAddress(), 1_000n);

    const chainId = (await ethers.provider.getNetwork()).chainId;
    const latest = await ethers.provider.getBlock('latest');
    const offer = {
      issuer: issuer.address,
      investor: investor.address,
      tokenAddress: await token.getAddress(),
      partition: ethers.ZeroHash,
      tokenId: 0n,
      amount: 250n,
      classId: 1n,
      nonceId: 1n,
      documentHash: ethers.keccak256(ethers.toUtf8Bytes('equipment-financing-note-transfer')),
      documentURI: 'ipfs://hazbase/corp-bond/transfer/2026-01',
      expiry: BigInt((latest?.timestamp ?? 0) + 3600),
      nonce: 11n,
    };
    const domain = {
      name: 'AgreementManager',
      version: '1',
      chainId,
      verifyingContract: await manager.getAddress(),
    };

    const issuerSig = await issuer.signTypedData(domain, offerTypes, offer);
    const offerId = computeOfferId(offer);

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
      dealer.address,
    );

    const investorSig = await investor.signTypedData(domain, offerTypes, offer);
    await expect(manager.connect(dealer).acceptOffer(offerId, investorSig)).to.emit(manager, 'OfferSettled');

    expect(await token.balanceOf(investor.address)).to.equal(250n);
    expect(await token.balanceOf(await manager.getAddress())).to.equal(0n);

    emitCorporateBondLedger({
      scenario: 'CBOND-CS-03',
      source: 'agreement-manager',
      ledger: {
        investor_holdings: {
          otc_transferred_units: 250,
        },
      },
      checks: {
        delegated_signature_matched: true,
        delegated_otc_settlement_complete: true,
      },
    });
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const ERC3475 = 0;
const ERC20 = 1;
const ERC721 = 2;
const ERC1155 = 3;

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

function expiresAt() {
  return BigInt(Math.floor(Date.now() / 1000) + 1800);
}

const hazamaDeliveryAttestationTypes = {
  HazamaDeliveryAttestation: [
    { name: 'templateId', type: 'string' },
    { name: 'orderId', type: 'string' },
    { name: 'orderKey', type: 'bytes32' },
    { name: 'termsHash', type: 'bytes32' },
    { name: 'sourceChainId', type: 'uint256' },
    { name: 'sourceContract', type: 'address' },
    { name: 'destinationNetwork', type: 'string' },
    { name: 'liquidTxid', type: 'string' },
    { name: 'paymentVout', type: 'uint32' },
    { name: 'paymentAssetId', type: 'string' },
    { name: 'paymentAmount', type: 'uint256' },
    { name: 'deliveryVout', type: 'uint32' },
    { name: 'deliveryAssetId', type: 'string' },
    { name: 'deliveryAmount', type: 'uint256' },
    { name: 'deliveryAddressHash', type: 'bytes32' },
    { name: 'confirmations', type: 'uint256' },
    { name: 'observedAt', type: 'uint64' },
    { name: 'expiresAt', type: 'uint64' },
  ],
};

async function hazamaDomain(manager: { getAddress(): Promise<string> }) {
  const network = await ethers.provider.getNetwork();
  return {
    name: 'HAZAMA Delivery Attestation',
    version: '1',
    chainId: network.chainId,
    verifyingContract: await manager.getAddress(),
  };
}

async function deliveryAttestation(manager: { getAddress(): Promise<string> }, input: {
  orderId: string;
  termsHash: string;
  liquidAssetId: string;
  deliveryTxid: string;
  amount: bigint;
  expiresAt?: bigint;
}) {
  const network = await ethers.provider.getNetwork();
  const observedAt = BigInt(Math.floor(Date.now() / 1000));
  return {
    templateId: 'evm-lock-to-liquid-delivery-v1',
    orderId: 'order-uuid-1',
    orderKey: input.orderId,
    termsHash: input.termsHash,
    sourceChainId: network.chainId,
    sourceContract: await manager.getAddress(),
    destinationNetwork: 'liquidtestnet',
    liquidTxid: input.deliveryTxid.slice(2),
    paymentVout: 0,
    paymentAssetId: id('lbtc').slice(2),
    paymentAmount: 10000n,
    deliveryVout: 1,
    deliveryAssetId: input.liquidAssetId.slice(2),
    deliveryAmount: input.amount,
    deliveryAddressHash: ethers.keccak256(ethers.toUtf8Bytes('tlq1buyer')),
    confirmations: 2n,
    observedAt,
    expiresAt: input.expiresAt ?? observedAt + 86400n,
  };
}

async function deployGenericFixture() {
  const [admin, backingOwner, other] = await ethers.getSigners();
  const manager = await ethers.deployContract('GenericRwaBackingLockManager', [admin.address]);
  await manager.waitForDeployment();

  const bondFactory = await ethers.getContractFactory('BondToken');
  const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor'],
  });
  await bond.waitForDeployment();
  await bond.createClass(1n, [{ key: 'name', value: 'Liquid Backed RWA' }]);
  await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2032-01-01' }]);
  await bond.issue(backingOwner.address, 1n, 1n, 100n);
  await bond.connect(backingOwner).setApprovalForAll(await manager.getAddress(), true);

  const erc20 = await ethers.deployContract('MockERC20');
  await erc20.waitForDeployment();
  await erc20.mint(backingOwner.address, 100n);
  await erc20.connect(backingOwner).approve(await manager.getAddress(), 100n);

  const erc721 = await ethers.deployContract('MockERC721');
  await erc721.waitForDeployment();
  await erc721.mint(backingOwner.address, 42n);
  await erc721.connect(backingOwner).approve(await manager.getAddress(), 42n);

  const erc1155 = await ethers.deployContract('MockERC1155');
  await erc1155.waitForDeployment();
  await erc1155.mint(backingOwner.address, 7n, 100n);
  await erc1155.connect(backingOwner).setApprovalForAll(await manager.getAddress(), true);

  return { admin, backingOwner, other, manager, bond, erc20, erc721, erc1155 };
}

describe('GenericRwaBackingLockManager', function () {
  it('locks, releases, and consumes ERC3475/BondToken backing', async function () {
    const { backingOwner, manager, bond } = await deployGenericFixture();
    const orderId = id('generic-bond');
    const liquidAssetId = id('liquid-rwa-asset');
    const termsHash = id('terms-bond');
    const lockExpiresAt = expiresAt();

    await expect(
      manager.lock(
        orderId,
        ERC3475,
        await bond.getAddress(),
        backingOwner.address,
        1n,
        1n,
        40n,
        liquidAssetId,
        termsHash,
        lockExpiresAt,
      ),
    )
      .to.emit(manager, 'BackingLocked')
      .withArgs(orderId, ERC3475, await bond.getAddress(), backingOwner.address, 1n, 1n, 40n, liquidAssetId, termsHash, lockExpiresAt);

    expect(await bond.balanceOf(backingOwner.address, 1n, 1n)).to.equal(60n);
    expect(await bond.balanceOf(await manager.getAddress(), 1n, 1n)).to.equal(40n);

    await manager.consume(orderId, id('delivery-bond'));
    const totals = await manager.backingBalance(ERC3475, await bond.getAddress(), 1n, 1n);
    expect(totals.locked).to.equal(0n);
    expect(totals.consumed).to.equal(40n);
  });

  it('locks and releases ERC20 backing', async function () {
    const { backingOwner, manager, erc20 } = await deployGenericFixture();
    const orderId = id('generic-erc20');

    await manager.lock(
      orderId,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      25n,
      id('liquid-rwa-asset'),
      id('terms-erc20'),
      expiresAt(),
    );

    expect(await erc20.balanceOf(backingOwner.address)).to.equal(75n);
    expect(await erc20.balanceOf(await manager.getAddress())).to.equal(25n);

    await manager.release(orderId, id('cancelled'));
    expect(await erc20.balanceOf(backingOwner.address)).to.equal(100n);
    expect(await erc20.balanceOf(await manager.getAddress())).to.equal(0n);
  });

  it('locks and releases ERC721 backing', async function () {
    const { backingOwner, manager, erc721 } = await deployGenericFixture();
    const orderId = id('generic-erc721');

    await manager.lock(
      orderId,
      ERC721,
      await erc721.getAddress(),
      backingOwner.address,
      42n,
      0n,
      1n,
      id('liquid-rwa-asset'),
      id('terms-erc721'),
      expiresAt(),
    );

    expect(await erc721.ownerOf(42n)).to.equal(await manager.getAddress());
    await manager.release(orderId, id('cancelled'));
    expect(await erc721.ownerOf(42n)).to.equal(backingOwner.address);
  });

  it('locks and releases ERC1155 backing', async function () {
    const { backingOwner, manager, erc1155 } = await deployGenericFixture();
    const orderId = id('generic-erc1155');

    await manager.lock(
      orderId,
      ERC1155,
      await erc1155.getAddress(),
      backingOwner.address,
      7n,
      0n,
      30n,
      id('liquid-rwa-asset'),
      id('terms-erc1155'),
      expiresAt(),
    );

    expect(await erc1155.balanceOf(backingOwner.address, 7n)).to.equal(70n);
    expect(await erc1155.balanceOf(await manager.getAddress(), 7n)).to.equal(30n);

    await manager.release(orderId, id('cancelled'));
    expect(await erc1155.balanceOf(backingOwner.address, 7n)).to.equal(100n);
    expect(await erc1155.balanceOf(await manager.getAddress(), 7n)).to.equal(0n);
  });

  it('rejects invalid token-standard identifiers and duplicate orders', async function () {
    const { backingOwner, manager, erc20 } = await deployGenericFixture();
    const orderId = id('generic-invalid');

    await expect(
      manager.lock(
        orderId,
        ERC20,
        await erc20.getAddress(),
        backingOwner.address,
        1n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-invalid'),
        expiresAt(),
      ),
    ).to.be.revertedWith('ERC20_ID_NONZERO');

    await manager.lock(
      orderId,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      10n,
      id('liquid-rwa-asset'),
      id('terms-valid'),
      expiresAt(),
    );

    await expect(
      manager.lock(
        orderId,
        ERC20,
        await erc20.getAddress(),
        backingOwner.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-duplicate'),
        expiresAt(),
      ),
    ).to.be.revertedWith('LOCK_EXISTS');
  });

  it('rejects invalid ERC721 and ERC1155 lock shapes', async function () {
    const { backingOwner, manager, erc721, erc1155 } = await deployGenericFixture();

    await expect(
      manager.lock(
        id('erc721-amount'),
        ERC721,
        await erc721.getAddress(),
        backingOwner.address,
        42n,
        0n,
        2n,
        id('liquid-rwa-asset'),
        id('terms-erc721-amount'),
        expiresAt(),
      ),
    ).to.be.revertedWith('ERC721_AMOUNT_NOT_ONE');

    await expect(
      manager.lock(
        id('erc1155-zero'),
        ERC1155,
        await erc1155.getAddress(),
        backingOwner.address,
        7n,
        0n,
        0n,
        id('liquid-rwa-asset'),
        id('terms-erc1155-zero'),
        expiresAt(),
      ),
    ).to.be.revertedWith('AMOUNT_ZERO');
  });

  it('prevents release after consume and consume after release', async function () {
    const { backingOwner, manager, erc20 } = await deployGenericFixture();
    const consumedOrder = id('generic-consumed');
    const releasedOrder = id('generic-released');

    await manager.lock(
      consumedOrder,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      10n,
      id('liquid-rwa-asset'),
      id('terms-consumed'),
      expiresAt(),
    );
    await manager.consume(consumedOrder, id('delivery-tx'));
    await expect(manager.release(consumedOrder, id('too-late'))).to.be.revertedWith('LOCK_NOT_LOCKED');

    await manager.lock(
      releasedOrder,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      10n,
      id('liquid-rwa-asset'),
      id('terms-released'),
      expiresAt(),
    );
    await manager.release(releasedOrder, id('cancelled'));
    await expect(manager.consume(releasedOrder, id('delivery-late'))).to.be.revertedWith('LOCK_NOT_LOCKED');
  });

  it('consumes with HAZAMA delivery attestations', async function () {
    const { backingOwner, manager, erc20 } = await deployGenericFixture();
    const approver = ethers.Wallet.createRandom();
    const orderId = id('generic-hazama-consume');
    const liquidAssetId = id('liquid-rwa-asset');
    const termsHash = id('terms-hazama');
    const deliveryTxid = id('delivery-hazama');

    await manager.setHazamaApprover(approver.address, true);
    await manager.setHazamaThreshold(1n);
    await manager.lock(
      orderId,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      10n,
      liquidAssetId,
      termsHash,
      expiresAt(),
    );

    const attestation = await deliveryAttestation(manager, {
      orderId,
      termsHash,
      liquidAssetId,
      deliveryTxid,
      amount: 10n,
    });
    const signature = await approver.signTypedData(
      await hazamaDomain(manager),
      hazamaDeliveryAttestationTypes,
      attestation,
    );

    await expect(manager.consumeWithAttestations(orderId, deliveryTxid, [attestation], [signature]))
      .to.emit(manager, 'BackingConsumed')
      .withArgs(orderId, deliveryTxid)
      .and.to.emit(manager, 'BackingConsumedWithAttestations')
      .withArgs(orderId, deliveryTxid, 1n);

    const lock = await manager.getLock(orderId);
    expect(lock.status).to.equal(3n);
    expect(lock.liquidDeliveryTxid).to.equal(deliveryTxid);
  });

  it('rejects HAZAMA attestations that do not satisfy threshold or lock facts', async function () {
    const { backingOwner, manager, erc20 } = await deployGenericFixture();
    const approver = ethers.Wallet.createRandom();
    const otherApprover = ethers.Wallet.createRandom();
    const orderId = id('generic-hazama-reject');
    const liquidAssetId = id('liquid-rwa-asset');
    const termsHash = id('terms-hazama-reject');
    const deliveryTxid = id('delivery-hazama-reject');

    await manager.setHazamaApprover(approver.address, true);
    await manager.setHazamaApprover(otherApprover.address, true);
    await manager.setHazamaThreshold(2n);
    await manager.lock(
      orderId,
      ERC20,
      await erc20.getAddress(),
      backingOwner.address,
      0n,
      0n,
      10n,
      liquidAssetId,
      termsHash,
      expiresAt(),
    );

    const attestation = await deliveryAttestation(manager, {
      orderId,
      termsHash,
      liquidAssetId,
      deliveryTxid,
      amount: 10n,
    });
    const domain = await hazamaDomain(manager);
    const signature = await approver.signTypedData(domain, hazamaDeliveryAttestationTypes, attestation);
    const secondSignature = await otherApprover.signTypedData(domain, hazamaDeliveryAttestationTypes, attestation);

    await expect(
      manager.consumeWithAttestations(orderId, deliveryTxid, [attestation], [signature]),
    ).to.be.revertedWith('HAZAMA_QUORUM_NOT_MET');
    await expect(
      manager.consumeWithAttestations(orderId, deliveryTxid, [attestation, attestation], [signature, signature]),
    ).to.be.revertedWith('HAZAMA_DUPLICATE_SIGNER');

    const mismatchedAssetAttestation = {
      ...attestation,
      deliveryAssetId: id('other-liquid-asset').slice(2),
    };
    const mismatchedAssetSignature = await approver.signTypedData(
      domain,
      hazamaDeliveryAttestationTypes,
      mismatchedAssetAttestation,
    );
    const mismatchedAssetSecondSignature = await otherApprover.signTypedData(
      domain,
      hazamaDeliveryAttestationTypes,
      mismatchedAssetAttestation,
    );
    await expect(
      manager.consumeWithAttestations(
        orderId,
        deliveryTxid,
        [mismatchedAssetAttestation, mismatchedAssetAttestation],
        [mismatchedAssetSignature, mismatchedAssetSecondSignature],
      ),
    ).to.be.revertedWith('ATTEST_ASSET');

    const expiredAttestation = await deliveryAttestation(manager, {
      orderId,
      termsHash,
      liquidAssetId,
      deliveryTxid,
      amount: 10n,
      expiresAt: 1n,
    });
    const expiredSignature = await approver.signTypedData(domain, hazamaDeliveryAttestationTypes, expiredAttestation);
    const expiredSecondSignature = await otherApprover.signTypedData(domain, hazamaDeliveryAttestationTypes, expiredAttestation);
    await expect(
      manager.consumeWithAttestations(orderId, deliveryTxid, [expiredAttestation, expiredAttestation], [expiredSignature, expiredSecondSignature]),
    ).to.be.revertedWith('ATTEST_EXPIRED');

    await manager.consumeWithAttestations(orderId, deliveryTxid, [attestation, attestation], [signature, secondSignature]);
    const totals = await manager.backingBalance(ERC20, await erc20.getAddress(), 0n, 0n);
    expect(totals.locked).to.equal(0n);
    expect(totals.consumed).to.equal(10n);
  });

  it('enforces roles and pause controls', async function () {
    const { backingOwner, other, manager, erc20 } = await deployGenericFixture();

    await expect(
      manager.connect(other).lock(
        id('generic-unauthorized'),
        ERC20,
        await erc20.getAddress(),
        backingOwner.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-unauthorized'),
        expiresAt(),
      ),
    ).to.be.reverted;

    await manager.pause();
    await expect(
      manager.lock(
        id('generic-paused'),
        ERC20,
        await erc20.getAddress(),
        backingOwner.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('terms-paused'),
        expiresAt(),
      ),
    ).to.be.reverted;
  });
});

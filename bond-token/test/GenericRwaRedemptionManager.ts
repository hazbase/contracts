import { expect } from 'chai';
import { ethers } from 'hardhat';

const ERC3475 = 0;
const ERC20 = 1;
const ERC721 = 2;
const ERC1155 = 3;

function id(value: string) {
  return ethers.keccak256(ethers.toUtf8Bytes(value));
}

async function deployRedemptionFixture() {
  const [admin, holder, other] = await ethers.getSigners();
  const manager = await ethers.deployContract('GenericRwaRedemptionManager', [admin.address]);
  await manager.waitForDeployment();

  const erc20 = await ethers.deployContract('MockERC20');
  await erc20.waitForDeployment();

  const erc721 = await ethers.deployContract('MockERC721');
  await erc721.waitForDeployment();

  const erc1155 = await ethers.deployContract('MockERC1155');
  await erc1155.waitForDeployment();

  return { admin, holder, other, manager, erc20, erc721, erc1155 };
}

describe('GenericRwaRedemptionManager', function () {
  it('records an ERC3475/BondToken redemption and totals by EVM asset identity', async function () {
    const { holder, manager, erc20 } = await deployRedemptionFixture();
    const redemptionId = id('redemption-bond');
    const liquidRecoveryTxid = id('liquid-recovery-tx');
    const evidenceHash = id('redemption-evidence');

    await expect(
      manager.recordRedemption(
        redemptionId,
        ERC3475,
        await erc20.getAddress(),
        holder.address,
        1n,
        1n,
        40n,
        id('liquid-rwa-asset'),
        liquidRecoveryTxid,
        0,
        id('terms-bond'),
        evidenceHash,
      ),
    )
      .to.emit(manager, 'RwaRedeemed')
      .withArgs(
        redemptionId,
        ERC3475,
        await erc20.getAddress(),
        holder.address,
        1n,
        1n,
        40n,
        id('liquid-rwa-asset'),
        liquidRecoveryTxid,
        0,
        id('terms-bond'),
        evidenceHash,
      );

    const record = await manager.getRedemption(redemptionId);
    expect(record.status).to.equal(1n);
    expect(record.holder).to.equal(holder.address);
    expect(record.amount).to.equal(40n);
    expect(await manager.redemptionBalance(ERC3475, await erc20.getAddress(), 1n, 1n)).to.equal(40n);
    expect(await manager.isLiquidRecoveryOutputUsed(liquidRecoveryTxid, 0)).to.equal(true);
  });

  it('rejects duplicate redemption ids and duplicate Liquid recovery outputs', async function () {
    const { holder, manager, erc20 } = await deployRedemptionFixture();
    const liquidRecoveryTxid = id('shared-liquid-recovery');

    await manager.recordRedemption(
      id('redemption-first'),
      ERC20,
      await erc20.getAddress(),
      holder.address,
      0n,
      0n,
      10n,
      id('liquid-rwa-asset'),
      liquidRecoveryTxid,
      1,
      id('terms-first'),
      id('evidence-first'),
    );

    await expect(
      manager.recordRedemption(
        id('redemption-first'),
        ERC20,
        await erc20.getAddress(),
        holder.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('other-liquid-recovery'),
        1,
        id('terms-duplicate-id'),
        id('evidence-duplicate-id'),
      ),
    ).to.be.revertedWith('REDEMPTION_EXISTS');

    await expect(
      manager.recordRedemption(
        id('redemption-second'),
        ERC20,
        await erc20.getAddress(),
        holder.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        liquidRecoveryTxid,
        1,
        id('terms-duplicate-output'),
        id('evidence-duplicate-output'),
      ),
    ).to.be.revertedWith('RECOVERY_OUTPUT_USED');
  });

  it('validates token standard specific shapes', async function () {
    const { holder, manager, erc20, erc721, erc1155 } = await deployRedemptionFixture();

    await expect(
      manager.recordRedemption(
        id('erc20-id'),
        ERC20,
        await erc20.getAddress(),
        holder.address,
        1n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('tx-erc20-id'),
        0,
        id('terms-erc20-id'),
        id('evidence-erc20-id'),
      ),
    ).to.be.revertedWith('ERC20_ID_NONZERO');

    await expect(
      manager.recordRedemption(
        id('erc721-amount'),
        ERC721,
        await erc721.getAddress(),
        holder.address,
        42n,
        0n,
        2n,
        id('liquid-rwa-asset'),
        id('tx-erc721-amount'),
        0,
        id('terms-erc721-amount'),
        id('evidence-erc721-amount'),
      ),
    ).to.be.revertedWith('ERC721_AMOUNT_NOT_ONE');

    await expect(
      manager.recordRedemption(
        id('erc1155-zero'),
        ERC1155,
        await erc1155.getAddress(),
        holder.address,
        7n,
        0n,
        0n,
        id('liquid-rwa-asset'),
        id('tx-erc1155-zero'),
        0,
        id('terms-erc1155-zero'),
        id('evidence-erc1155-zero'),
      ),
    ).to.be.revertedWith('AMOUNT_ZERO');
  });

  it('enforces roles and pause controls', async function () {
    const { holder, other, manager, erc20 } = await deployRedemptionFixture();

    await expect(
      manager.connect(other).recordRedemption(
        id('unauthorized'),
        ERC20,
        await erc20.getAddress(),
        holder.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('tx-unauthorized'),
        0,
        id('terms-unauthorized'),
        id('evidence-unauthorized'),
      ),
    ).to.be.reverted;

    await manager.pause();
    await expect(
      manager.recordRedemption(
        id('paused'),
        ERC20,
        await erc20.getAddress(),
        holder.address,
        0n,
        0n,
        10n,
        id('liquid-rwa-asset'),
        id('tx-paused'),
        0,
        id('terms-paused'),
        id('evidence-paused'),
      ),
    ).to.be.reverted;
  });
});

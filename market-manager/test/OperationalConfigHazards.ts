import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

async function deployMarketFixture() {
  const [admin, seller, buyer] = await ethers.getSigners();
  const assetToken = await ethers.deployContract('MockERC721', ['Config Hazard Asset', 'CHA']);
  const paymentToken = await ethers.deployContract('MockERC20', ['Stable Token', 'USDS']);
  const strictWhitelist = await ethers.deployContract('MockWhitelist');
  const permissiveWhitelist = await ethers.deployContract('MockWhitelist');
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const marketFactory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(marketFactory, [admin.address, splitter.target, 100, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();

  await assetToken.mint(seller.address);
  await assetToken.mint(seller.address);
  await assetToken.connect(seller).setApprovalForAll(market.target, true);
  await paymentToken.mint(buyer.address, 5_000n);
  await paymentToken.connect(buyer).approve(market.target, 5_000n);

  return { seller, buyer, assetToken, paymentToken, strictWhitelist, permissiveWhitelist, market };
}

describe('MarketManager configuration-hazard coverage', function () {
  it('emits config ledger for CFG-01 whitelist pointer drift on market fills', async function () {
    const { seller, buyer, assetToken, strictWhitelist, permissiveWhitelist, market } = await deployMarketFixture();

    await strictWhitelist.setWhitelisted(buyer.address, false);
    await permissiveWhitelist.setWhitelisted(buyer.address, true);
    await market.setWhitelist(strictWhitelist.target);

    await market.connect(seller).createAsk(
      { kind: 1, token: assetToken.target, id: 1n, nonceId: 0n, amount: 0n },
      100n,
      ethers.ZeroAddress,
      1n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash,
    );

    await expect(
      market.connect(buyer).fillAsk(0, 1n, { value: 100n }),
    ).to.be.revertedWith('KYCfail');

    await market.setWhitelist(permissiveWhitelist.target);
    await expect(
      market.connect(buyer).fillAsk(0, 1n, { value: 100n }),
    ).to.emit(market, 'AskFilled');

    emitConfigLedger({
      scenario: 'CFG-01',
      source: 'market-manager',
      ledger: {
        admission_boundary_changed: true,
      },
      checks: {
        whitelist_pointer_drift_changes_fill_boundary: true,
      },
    });
  });

  it('emits config ledger for CFG-02 payment token drift hazard on live asks', async function () {
    const { seller, buyer, assetToken, paymentToken, market } = await deployMarketFixture();

    await market.setPaymentToken(paymentToken.target, true);
    await market.connect(seller).createAsk(
      { kind: 1, token: assetToken.target, id: 1n, nonceId: 0n, amount: 0n },
      1_000n,
      paymentToken.target,
      1n,
      0,
      0,
      0,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
      ethers.ZeroHash,
    );

    const chainId = Number((await ethers.provider.getNetwork()).chainId);
    const domain = {
      name: 'MarketManager',
      version: '1',
      chainId,
      verifyingContract: await market.getAddress(),
    };
    const types = {
      Asset: [
        { name: 'kind', type: 'uint8' },
        { name: 'token', type: 'address' },
        { name: 'id', type: 'uint256' },
        { name: 'nonceId', type: 'uint256' },
        { name: 'amount', type: 'uint256' },
      ],
      Voucher: [
        { name: 'asset', type: 'Asset' },
        { name: 'price', type: 'uint256' },
        { name: 'paymentToken', type: 'address' },
        { name: 'quantity', type: 'uint256' },
        { name: 'maxPerWallet', type: 'uint64' },
        { name: 'startTime', type: 'uint64' },
        { name: 'endTime', type: 'uint64' },
        { name: 'royaltyReceiver', type: 'address' },
        { name: 'royaltyBps', type: 'uint16' },
        { name: 'salt', type: 'uint256' },
        { name: 'seller', type: 'address' },
      ],
    };
    const voucher = {
      asset: { kind: 1, token: await assetToken.getAddress(), id: 2n, nonceId: 0n, amount: 0n },
      price: 1_500n,
      paymentToken: await paymentToken.getAddress(),
      quantity: 1n,
      maxPerWallet: 0,
      startTime: 0,
      endTime: 0,
      royaltyReceiver: ethers.ZeroAddress,
      royaltyBps: 0,
      salt: 88n,
      seller: seller.address,
    };
    const sig = await seller.signTypedData(domain, types, voucher);

    await market.setPaymentToken(paymentToken.target, false);
    await expect(market.connect(buyer).fillAsk(0, 1n)).to.emit(market, 'AskFilled');
    await expect(market.connect(buyer).fillVoucher(voucher, 1n, sig)).to.be.revertedWith('payToken !allowed');

    emitConfigLedger({
      scenario: 'CFG-02',
      source: 'market-manager',
      ledger: {
        active_ask_payment_token_state: 'fill_ask_unaffected_fill_voucher_blocked',
      },
      checks: {
        fill_ask_hazard_observed: true,
        fill_voucher_safe_fail: true,
      },
    });
  });
});

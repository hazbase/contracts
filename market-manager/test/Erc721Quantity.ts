import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// An ERC-721 ask moves exactly one tokenId regardless of `quantity`. If `quantity > 1`
// were allowed, a buyer paying price*quantity would receive a single NFT (over-payment).
// createAsk must therefore force quantity == 1 for the ERC721 asset kind (enum index 1).

async function deployMarket(admin: string) {
  const splitter = await ethers.deployContract('MockSplitter', [false]);
  const factory = await ethers.getContractFactory('MarketManager');
  const market = await upgrades.deployProxy(factory, [admin, splitter.target, 0, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor', 'state-variable-immutable'],
  });
  await market.waitForDeployment();
  return market;
}

describe('MarketManager ERC721 ask quantity', function () {
  it('reverts when an ERC721 ask is created with quantity != 1', async function () {
    const [admin, seller] = await ethers.getSigners();
    const nft = await ethers.deployContract('MockERC721', ['Asset NFT', 'ANFT']);
    const market = await deployMarket(admin.address);

    await nft.mint(seller.address); // tokenId 1
    await nft.connect(seller).approve(market.target, 1n);

    await expect(
      market.connect(seller).createAsk(
        { kind: 1, token: nft.target, id: 1n, nonceId: 0n, amount: 0n },
        100n,
        ethers.ZeroAddress,
        2n, // quantity > 1 — illegal for ERC721
        0,
        0,
        0,
        ethers.ZeroAddress,
        0,
        ethers.ZeroAddress,
        ethers.ZeroHash,
      ),
    ).to.be.revertedWith('ERC721: quantity must be 1');
  });

  it('accepts an ERC721 ask with quantity == 1 and escrows the token', async function () {
    const [admin, seller] = await ethers.getSigners();
    const nft = await ethers.deployContract('MockERC721', ['Asset NFT', 'ANFT']);
    const market = await deployMarket(admin.address);

    await nft.mint(seller.address); // tokenId 1
    await nft.connect(seller).approve(market.target, 1n);

    await expect(
      market.connect(seller).createAsk(
        { kind: 1, token: nft.target, id: 1n, nonceId: 0n, amount: 0n },
        100n,
        ethers.ZeroAddress,
        1n, // the only legal quantity for ERC721
        0,
        0,
        0,
        ethers.ZeroAddress,
        0,
        ethers.ZeroAddress,
        ethers.ZeroHash,
      ),
    ).to.emit(market, 'AskCreated');

    // The single NFT is genuinely escrowed by the market.
    expect(await nft.ownerOf(1n)).to.equal(market.target);
    const ask = await market.ask(0);
    expect(ask.quantity).to.equal(1n);
  });
});

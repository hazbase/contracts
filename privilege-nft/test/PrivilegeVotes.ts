import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// PrivilegeNFT initialize(name, symbol, baseURI, admin, forwarders, royaltyReceiver, royaltyFeeNumerator)
async function deployNFT(admin: string) {
  const factory = await ethers.getContractFactory('PrivilegeNFT');
  const nft = await upgrades.deployProxy(
    factory,
    ['Privilege', 'PRV', 'ipfs://base/', admin, [], admin, 0],
    { kind: 'uups', initializer: 'initialize' },
  );
  await nft.waitForDeployment();
  return nft;
}

// safeMint(to, uri, exp, tier)
const FUTURE = 4_000_000_000n; // far-future expiry

describe('PrivilegeNFT tier-weighted voting + soulbound', function () {
  describe('tier weight is the voting unit', function () {
    it('mint + self-delegate yields votes equal to the token tier (not 1-per-token)', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 3);
      // ERC721Votes: units only count once delegated.
      expect(await nft.getVotes(alice.address)).to.equal(0n);

      await nft.connect(alice).delegate(alice.address);
      expect(await nft.getVotes(alice.address)).to.equal(3n);
    });

    it('a second token adds its own tier weight to the holder', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 3);
      await nft.safeMint(alice.address, 'ipfs://b', FUTURE, 5);
      await nft.connect(alice).delegate(alice.address);
      expect(await nft.getVotes(alice.address)).to.equal(8n);
    });
  });

  describe('setTier takes effect immediately without re-delegation', function () {
    it('raising the tier increases getVotes for the already-delegated owner', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      const id = await nft.safeMint.staticCall(alice.address, 'ipfs://a', FUTURE, 1);
      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 1);
      await nft.connect(alice).delegate(alice.address);
      expect(await nft.getVotes(alice.address)).to.equal(1n);

      // setTier syncs the live ERC721Votes checkpoints, so votes change
      // immediately — the owner does NOT need to re-delegate for it to count.
      await nft.setTier(id, 7);
      expect(await nft.getVotes(alice.address)).to.equal(7n);
    });

    it('lowering the tier decreases getVotes immediately', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      const id = await nft.safeMint.staticCall(alice.address, 'ipfs://a', FUTURE, 9);
      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 9);
      await nft.connect(alice).delegate(alice.address);
      expect(await nft.getVotes(alice.address)).to.equal(9n);

      await nft.setTier(id, 2);
      expect(await nft.getVotes(alice.address)).to.equal(2n);
    });

    it('the total-supply checkpoint stays consistent with the tier-weighted votes', async function () {
      const [admin, alice, bob] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 3);
      await nft.safeMint(bob.address, 'ipfs://b', FUTURE, 5);
      // Total voting supply is tracked at mint regardless of delegation.
      const minted = await ethers.provider.getBlockNumber();
      await ethers.provider.send('evm_mine', []);
      expect(await nft.getPastTotalSupply(minted)).to.equal(8n);

      const id0 = 0n; // first minted token id (alice, tier 3)
      await nft.setTier(id0, 10); // +7
      const bumped = await ethers.provider.getBlockNumber();
      await ethers.provider.send('evm_mine', []);
      expect(await nft.getPastTotalSupply(bumped)).to.equal(15n);
    });
  });

  describe('transfers move the tier weight, not a flat 1', function () {
    it('transferring a token moves its tier weight between delegated holders', async function () {
      const [admin, alice, bob] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      const id = await nft.safeMint.staticCall(alice.address, 'ipfs://a', FUTURE, 4);
      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 4);
      await nft.connect(alice).delegate(alice.address);
      await nft.connect(bob).delegate(bob.address);
      expect(await nft.getVotes(alice.address)).to.equal(4n);
      expect(await nft.getVotes(bob.address)).to.equal(0n);

      await nft.connect(alice).transferFrom(alice.address, bob.address, id);
      expect(await nft.getVotes(alice.address)).to.equal(0n);
      expect(await nft.getVotes(bob.address)).to.equal(4n);
    });
  });

  describe('soulbound mode blocks EOA->EOA transfers', function () {
    it('reverts holder-to-holder transfer once soulbound is enabled, but still allows minting', async function () {
      const [admin, alice, bob] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);

      const id = await nft.safeMint.staticCall(alice.address, 'ipfs://a', FUTURE, 1);
      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 1);

      await nft.setSoulbound(true);
      await expect(
        nft.connect(alice).transferFrom(alice.address, bob.address, id),
      ).to.be.revertedWithCustomError(nft, 'SoulboundErr');

      // Minting (from address(0)) is exempt from the soulbound rule.
      await expect(nft.safeMint(bob.address, 'ipfs://c', FUTURE, 1)).to.not.be.reverted;

      // Turning it back off restores transferability.
      await nft.setSoulbound(false);
      await expect(
        nft.connect(alice).transferFrom(alice.address, bob.address, id),
      ).to.not.be.reverted;
    });
  });

  describe('access control', function () {
    it('safeMint is restricted to MINTER_ROLE', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);
      await expect(
        nft.connect(alice).safeMint(alice.address, 'ipfs://a', FUTURE, 1),
      ).to.be.reverted;
    });

    it('setTier is restricted to MINTER_ROLE', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);
      await nft.safeMint(alice.address, 'ipfs://a', FUTURE, 1);
      await expect(nft.connect(alice).setTier(0, 5)).to.be.reverted;
    });

    it('setSoulbound is restricted to ADMIN_ROLE', async function () {
      const [admin, alice] = await ethers.getSigners();
      const nft = await deployNFT(admin.address);
      await expect(nft.connect(alice).setSoulbound(true)).to.be.reverted;
    });
  });
});

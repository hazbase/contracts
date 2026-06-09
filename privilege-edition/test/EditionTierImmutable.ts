import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// PrivilegeEdition initialize(baseURI, admin, forwarders, royaltyReceiver, royaltyFee)
async function deployEdition(admin: string) {
  const factory = await ethers.getContractFactory('PrivilegeEdition');
  const ed = await upgrades.deployProxy(
    factory,
    ['ipfs://base/', admin, [], admin, 0],
    { kind: 'uups', initializer: 'initialize' },
  );
  await ed.waitForDeployment();
  return ed;
}

// mint(to, id, amt, uri_, tier, exp, rType)
const NEVER = 0n;

async function now() {
  return BigInt((await ethers.provider.getBlock('latest'))!.timestamp);
}

describe('PrivilegeEdition tier immutability + expiry', function () {
  describe('voting units = tier x amount', function () {
    it('credits tier-weighted units that count after delegation', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      await ed.mint(alice.address, 1, 10, '', 2, NEVER, 0);
      expect(await ed.getVotes(alice.address)).to.equal(0n); // not yet delegated
      await ed.connect(alice).delegate(alice.address);
      expect(await ed.getVotes(alice.address)).to.equal(20n); // 2 * 10
    });
  });

  describe('edition tier is fixed at first mint and cannot change afterward', function () {
    it('setTier reverts AlreadyMinted once any amount has been minted', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      await ed.mint(alice.address, 1, 1, '', 2, NEVER, 0);
      await expect(ed.setTier(1, 9)).to.be.revertedWithCustomError(ed, 'AlreadyMinted');
    });

    it('a later mint of the same id cannot change the tier used for voting accounting', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      // First mint establishes tier = 2 for id 1.
      await ed.mint(alice.address, 1, 10, '', 2, NEVER, 0);
      // Second mint passes tier = 99, but the edition tier stays 2 (immutable).
      await ed.mint(alice.address, 1, 5, '', 99, NEVER, 0);

      await ed.connect(alice).delegate(alice.address);
      // 15 tokens * tier 2 = 30 — NOT 10*2 + 5*99. Proves the second mint's tier was ignored.
      expect(await ed.getVotes(alice.address)).to.equal(30n);
    });

    it('transferring the full balance after a second mint zeroes votes without underflow', async function () {
      const [admin, alice, bob] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      await ed.mint(alice.address, 1, 10, '', 2, NEVER, 0);
      await ed.mint(alice.address, 1, 5, '', 99, NEVER, 0); // tier 99 ignored
      await ed.connect(alice).delegate(alice.address);
      await ed.connect(bob).delegate(bob.address);
      expect(await ed.getVotes(alice.address)).to.equal(30n);

      // If the tier had been corrupted to 99, this transfer would underflow _votesBalance and revert.
      await ed.connect(alice).safeTransferFrom(alice.address, bob.address, 1, 15, '0x');
      expect(await ed.getVotes(alice.address)).to.equal(0n);
      expect(await ed.getVotes(bob.address)).to.equal(30n);
    });
  });

  describe('expiry semantics', function () {
    it('expiresAt == 0 means never expires: sweepExpired finds nothing even far in the future', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      await ed.mint(alice.address, 7, 10, '', 1, NEVER, 0);
      await ethers.provider.send('evm_increaseTime', [10 * 365 * 24 * 3600]); // +10y
      await ethers.provider.send('evm_mine', []);

      await expect(ed.connect(alice).sweepExpired([7])).to.be.revertedWithCustomError(ed, 'NoExpired');
      expect(await ed.balanceOf(alice.address, 7)).to.equal(10n);
    });

    it('a positive expiry can be swept after it passes, dropping the holder votes', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);

      const exp = (await now()) + 100n;
      await ed.mint(alice.address, 8, 10, '', 3, exp, 0);
      await ed.connect(alice).delegate(alice.address);
      expect(await ed.getVotes(alice.address)).to.equal(30n);

      await ethers.provider.send('evm_increaseTime', [200]);
      await ethers.provider.send('evm_mine', []);

      await ed.connect(alice).sweepExpired([8]);
      expect(await ed.balanceOf(alice.address, 8)).to.equal(0n);
      expect(await ed.getVotes(alice.address)).to.equal(0n);
    });
  });

  describe('access control', function () {
    it('mint is restricted to MINTER_ROLE', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);
      await expect(ed.connect(alice).mint(alice.address, 1, 1, '', 1, NEVER, 0)).to.be.reverted;
    });

    it('sweepExpiredFrom is restricted to MINTER_ROLE', async function () {
      const [admin, alice] = await ethers.getSigners();
      const ed = await deployEdition(admin.address);
      await expect(ed.connect(alice).sweepExpiredFrom(alice.address, [1])).to.be.reverted;
    });
  });
});

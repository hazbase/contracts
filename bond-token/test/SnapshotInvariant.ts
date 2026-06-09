import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

// Invariant/fuzz for BondToken's lazy write-once snapshots.
//
// Property under test: balanceOfAt(holder, S) and totalSupplyAt(S) equal the holder balance /
// total supply *at the instant snapshot S was created*, and that value is IMMUTABLE — no later
// mint / transfer / redeem / snapshot may ever change a finalized snapshot's reported values.
// We drive a long pseudo-random sequence of mutations, mirror them in a JS ledger, and after the
// whole run re-read every past snapshot to confirm none drifted.

// Deterministic 64-bit LCG so any failure is reproducible (no Math.random()).
function makeRng(seedInit: bigint) {
  let seed = seedInit;
  const MASK = (1n << 64n) - 1n;
  return (n: number) => {
    seed = (seed * 6364136223846793005n + 1442695040888963407n) & MASK;
    return Number((seed >> 33n) % BigInt(n));
  };
}

const CLASS = 1n;
const NONCE = 1n;

async function deployBond(admin: string) {
  const factory = await ethers.getContractFactory('BondToken');
  const bond = await upgrades.deployProxy(factory, [admin, []], {
    kind: 'uups',
    initializer: 'initialize',
    unsafeAllow: ['constructor'],
  });
  await bond.waitForDeployment();
  await bond.createClass(CLASS, [{ key: 'name', value: 'Series A' }]);
  await bond.createNonce(CLASS, NONCE, [{ key: 'maturity', value: '2030-01-01' }]);
  return bond;
}

describe('BondToken snapshot immutability (invariant/fuzz)', function () {
  it('keeps every finalized snapshot constant across a long random mutation sequence', async function () {
    const [admin, alice, bob, carol] = await ethers.getSigners();
    const bond = await deployBond(admin.address);

    const holders = [alice, bob, carol];
    const ledger = new Map<string, bigint>(holders.map((h) => [h.address, 0n]));
    let supply = 0n;

    // Seed initial balances in epoch 0 (before the first snapshot).
    await bond.issue(alice.address, CLASS, NONCE, 100n);
    await bond.issue(bob.address, CLASS, NONCE, 50n);
    ledger.set(alice.address, 100n);
    ledger.set(bob.address, 50n);
    supply = 150n;

    const rng = makeRng(0xdeadbeefn);
    const ROUNDS = 10;
    const OPS_PER_ROUND = 4;

    // snapshotId -> expected { balances per holder, supply } captured at snapshot creation.
    const expectedBal: Map<number, Map<string, bigint>> = new Map();
    const expectedSupply: Map<number, bigint> = new Map();
    let snapId = 0;

    for (let r = 0; r < ROUNDS; r++) {
      for (let k = 0; k < OPS_PER_ROUND; k++) {
        const op = rng(3);
        if (op === 0) {
          // issue
          const to = holders[rng(holders.length)];
          const amt = BigInt(1 + rng(50));
          await bond.issue(to.address, CLASS, NONCE, amt);
          ledger.set(to.address, ledger.get(to.address)! + amt);
          supply += amt;
        } else if (op === 1) {
          // transfer from a holder that has balance
          const funded = holders.filter((h) => ledger.get(h.address)! > 0n);
          if (funded.length === 0) {
            k--; // retry as a different op next iteration would skip; just redo this slot
            const to = holders[rng(holders.length)];
            const amt = BigInt(1 + rng(50));
            await bond.issue(to.address, CLASS, NONCE, amt);
            ledger.set(to.address, ledger.get(to.address)! + amt);
            supply += amt;
            continue;
          }
          const from = funded[rng(funded.length)];
          const others = holders.filter((h) => h.address !== from.address);
          const to = others[rng(others.length)]; // never self-transfer (contract reverts SELF_TRANSFER)
          const max = ledger.get(from.address)!;
          const amt = BigInt(1 + rng(Number(max < 40n ? max : 40n)));
          await bond.connect(from).transfer(to.address, CLASS, NONCE, amt);
          ledger.set(from.address, ledger.get(from.address)! - amt);
          ledger.set(to.address, ledger.get(to.address)! + amt);
        } else {
          // redeem (burn) from a holder that has balance
          const funded = holders.filter((h) => ledger.get(h.address)! > 0n);
          if (funded.length === 0) {
            const to = holders[rng(holders.length)];
            const amt = BigInt(1 + rng(50));
            await bond.issue(to.address, CLASS, NONCE, amt);
            ledger.set(to.address, ledger.get(to.address)! + amt);
            supply += amt;
            continue;
          }
          const who = funded[rng(funded.length)];
          const max = ledger.get(who.address)!;
          const amt = BigInt(1 + rng(Number(max < 30n ? max : 30n)));
          await bond.connect(who).redeem(CLASS, NONCE, amt);
          ledger.set(who.address, ledger.get(who.address)! - amt);
          supply -= amt;
        }
      }

      // Finalize the epoch. snapshot() returns ++_snapId, so the new id is the call count.
      await bond.snapshot();
      snapId += 1;

      // Capture the ledger state AT snapshot creation — this is what balanceOfAt(_, snapId) must
      // forever report.
      const snap = new Map<string, bigint>();
      for (const h of holders) snap.set(h.address, ledger.get(h.address)!);
      expectedBal.set(snapId, snap);
      expectedSupply.set(snapId, supply);
    }

    // 1) Current live balances match the ledger (mutation bookkeeping is correct).
    for (const h of holders) {
      expect(await bond.balanceOf(h.address, CLASS, NONCE)).to.equal(ledger.get(h.address)!);
    }

    // 2) Immutability + internal conservation for EVERY finalized snapshot, read AFTER the whole run.
    for (let s = 1; s <= snapId; s++) {
      let sum = 0n;
      for (const h of holders) {
        const got = await bond.balanceOfAt(h.address, CLASS, NONCE, s);
        expect(got, `balanceOfAt(${h.address}, ${s})`).to.equal(expectedBal.get(s)!.get(h.address)!);
        sum += got;
      }
      const ts = await bond.totalSupplyAt(CLASS, NONCE, s);
      expect(ts, `totalSupplyAt(${s})`).to.equal(expectedSupply.get(s)!);
      // Conservation: holder balances at snapshot s sum to the recorded supply at s.
      expect(sum, `sum==supply @ ${s}`).to.equal(ts);
    }
  });

  it('reports current values for snapshot ids at or beyond the latest snapshot', async function () {
    const [admin, alice] = await ethers.getSigners();
    const bond = await deployBond(admin.address);

    await bond.issue(alice.address, CLASS, NONCE, 70n);
    await bond.snapshot(); // id 1
    await bond.snapshot(); // id 2

    // Query an id beyond the latest snapshot: no recorded entry >= id => current balance/supply.
    expect(await bond.balanceOfAt(alice.address, CLASS, NONCE, 99n)).to.equal(70n);
    expect(await bond.totalSupplyAt(CLASS, NONCE, 99n)).to.equal(70n);

    // A mutation after snapshot 2 must not retroactively change snapshots 1 or 2.
    await bond.connect(alice).redeem(CLASS, NONCE, 20n);
    expect(await bond.balanceOfAt(alice.address, CLASS, NONCE, 1n)).to.equal(70n);
    expect(await bond.balanceOfAt(alice.address, CLASS, NONCE, 2n)).to.equal(70n);
    expect(await bond.balanceOf(alice.address, CLASS, NONCE)).to.equal(50n);
  });
});

import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('BondToken operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-01 bond-token setter abuse rejection', async function () {
    const [admin, rogue] = await ethers.getSigners();
    const bondFactory = await ethers.getContractFactory('BondToken');
    const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await bond.waitForDeployment();

    await expect(bond.connect(rogue).setWhitelist(rogue.address)).to.be.reverted;
    await expect(bond.connect(rogue).setClassTransferable(1n, true)).to.be.reverted;
    await expect(bond.connect(rogue).snapshot()).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-01',
      source: 'bond-token',
      checks: {
        bond_minter_setters_blocked: true,
      },
    });
  });
});

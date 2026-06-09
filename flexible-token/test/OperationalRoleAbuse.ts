import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitRoleLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ROLE_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ROLE_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('FlexibleToken operator role-abuse coverage', function () {
  it('emits role ledger for ROLE-01 flexible-token setter abuse rejection', async function () {
    const [admin, rogue] = await ethers.getSigners();
    const factory = await ethers.getContractFactory('FlexibleToken');
    const token = await upgrades.deployProxy(
      factory,
      ['Role Abuse Equity', 'RBE', admin.address, 1_000n, 4_000n, 0, true, admin.address, []],
      {
        kind: 'uups',
        initializer: 'initialize',
      },
    );
    await token.waitForDeployment();

    await expect(token.connect(rogue).setWhitelist(rogue.address)).to.be.reverted;
    await expect(token.connect(rogue).setCap(10_000n)).to.be.reverted;

    emitRoleLedger({
      scenario: 'ROLE-01',
      source: 'flexible-token',
      checks: {
        flexible_token_setters_blocked: true,
      },
    });
  });
});

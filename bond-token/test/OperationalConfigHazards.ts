import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('BondToken configuration-hazard coverage', function () {
  it('emits config ledger for CFG-01 whitelist pointer drift on bond transfers', async function () {
    const [admin, alice, bob] = await ethers.getSigners();
    const whitelist = await ethers.deployContract('MockWhitelist');
    const bondFactory = await ethers.getContractFactory('BondToken');
    const bond = await upgrades.deployProxy(bondFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await bond.waitForDeployment();

    await bond.createClass(1n, [{ key: 'name', value: 'Config Drift Bond' }]);
    await bond.createNonce(1n, 1n, [{ key: 'maturity', value: '2031-01-01' }]);
    await bond.issue(alice.address, 1n, 1n, 100n);

    await whitelist.setWhitelisted(alice.address, true);
    await whitelist.setWhitelisted(bob.address, false);
    await bond.setWhitelist(whitelist.target);

    await expect(
      bond.connect(alice).transfer(bob.address, 1n, 1n, 10n),
    ).to.be.revertedWith('RECIP_NOT_WHITELISTED');

    await bond.setWhitelist(ethers.ZeroAddress);
    await expect(
      bond.connect(alice).transfer(bob.address, 1n, 1n, 10n),
    ).to.emit(bond, 'Transfer').withArgs(alice.address, bob.address, 1n, 1n, 10n);

    emitConfigLedger({
      scenario: 'CFG-01',
      source: 'bond-token',
      ledger: {
        admission_boundary_changed: true,
      },
      checks: {
        zero_whitelist_disables_token_checks: true,
      },
    });
  });
});

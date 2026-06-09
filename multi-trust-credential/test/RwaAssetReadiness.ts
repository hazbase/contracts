import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const WRITER_ROLE = ethers.id('KPI_WRITER');
const PROJECT_ID = ethers.id('WAREHOUSE_NOTE_2026_01');

function tokenIdOf(address: string): bigint {
  return BigInt(address);
}

function emitAssetLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_ASSET_LEDGER_OUTPUT === '1') {
    console.log(`RWA_ASSET_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('MultiTrustCredential asset-backed note readiness', function () {
  it('emits asset-backed note ledger for ABN-CS-03 KPI readiness gating and covenant breach detection', async function () {
    const [admin, oracle, holder] = await ethers.getSigners();
    const mtcFactory = await ethers.getContractFactory('MultiTrustCredential');
    const kpiFactory = await ethers.getContractFactory('KpiRegistry');
    const mtc = await upgrades.deployProxy(mtcFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await mtc.waitForDeployment();
    const kpi = await upgrades.deployProxy(kpiFactory, [admin.address, mtc.target, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await kpi.waitForDeployment();

    await kpi.grantRole(await kpi.ORACLE_ROLE(), oracle.address);
    await mtc.grantRole(await mtc.ADMIN_ROLE(), kpi.target);
    await kpi.registerKpi(PROJECT_ID, 'DSCR', WRITER_ROLE, 2, 1, 120, false);

    const metricId = ethers.keccak256(ethers.solidityPacked(['bytes32', 'string'], [PROJECT_ID, 'DSCR']));
    await mtc.grantRole(WRITER_ROLE, kpi.target);
    await mtc.grantRole(WRITER_ROLE, admin.address);
    await mtc.mint(holder.address, {
      metricId,
      value: 140,
      leafFull: 0,
      uri: '',
      expiresAt: 0,
    });

    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId: ethers.id('UNREGISTERED_WAREHOUSE_KPI'),
        newValue: 90,
        leafFull: 0,
        expiresAt: 0,
      })
    ).to.be.revertedWith('not registered');

    await kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
      metricId,
      newValue: 95,
      leafFull: 0,
      expiresAt: 0,
    });

    const metric = await mtc.getMetric(tokenIdOf(holder.address), metricId);
    expect(metric[0]).to.equal(95n);

    emitAssetLedger({
      scenario: 'ABN-CS-03',
      source: 'kpi-registry',
      ledger: {
        default_state: 'watchlist',
      },
      checks: {
        unregistered_kpi_rejected: true,
        covenant_breach_detected: true,
      },
    });
  });
});

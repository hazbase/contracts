import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const WRITER_ROLE = ethers.id('KPI_WRITER');
const METRIC_ID = ethers.id('CFG_KPI_METRIC');
const PROJECT_ID = ethers.id('CFG_PROJECT_ALPHA');
const LEAF_FULL = 123n;

function emitConfigLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_CFG_LEDGER_OUTPUT === '1') {
    console.log(`RWA_CFG_LEDGER::${JSON.stringify(entry)}`);
  }
}

function tokenIdOf(address: string): bigint {
  return BigInt(address);
}

describe('MultiTrustCredential configuration-hazard coverage', function () {
  it('emits config ledger for CFG-03 proof and KPI wiring that stays gated until fully wired', async function () {
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
    const verifier = await ethers.deployContract('MockVerifier');

    await mtc.registerMetric(METRIC_ID, 'Config Hazard Metric', WRITER_ROLE, true, 0);
    await mtc.grantRole(WRITER_ROLE, admin.address);
    await mtc.mint(holder.address, {
      metricId: METRIC_ID,
      value: 0,
      leafFull: LEAF_FULL,
      uri: '',
      expiresAt: 0,
    });

    const proofA: [bigint, bigint] = [0n, 0n];
    const proofB: [[bigint, bigint], [bigint, bigint]] = [[0n, 0n], [0n, 0n]];
    const proofC: [bigint, bigint] = [0n, 0n];
    const pubSignals: [bigint, bigint, bigint, bigint, bigint, bigint] = [
      0n,
      LEAF_FULL,
      1n,
      tokenIdOf(holder.address),
      0n,
      999n,
    ];

    await expect(
      mtc.proveMetric(tokenIdOf(holder.address), METRIC_ID, proofA, proofB, proofC, pubSignals),
    ).to.be.revertedWith('need verifier');

    await kpi.grantRole(await kpi.ORACLE_ROLE(), oracle.address);
    await expect(
      kpi.registerKpi(PROJECT_ID, 'Utilization', WRITER_ROLE, 2, 1, 80, false),
    ).to.be.reverted;

    await mtc.grantRole(await mtc.ADMIN_ROLE(), kpi.target);
    await kpi.registerKpi(PROJECT_ID, 'Utilization', WRITER_ROLE, 2, 1, 80, false);

    const metricId = ethers.keccak256(ethers.solidityPacked(['bytes32', 'string'], [PROJECT_ID, 'Utilization']));
    await mtc.updateMetric(tokenIdOf(holder.address), {
      metricId,
      newValue: 75,
      leafFull: 0,
      expiresAt: 0,
    });

    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId,
        newValue: 81,
        leafFull: 0,
        expiresAt: 0,
      }),
    ).to.be.revertedWith('role');

    await mtc.grantRole(WRITER_ROLE, kpi.target);
    await mtc.updateVerifier(verifier.target);
    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId,
        newValue: 81,
        leafFull: 0,
        expiresAt: 0,
      }),
    ).to.emit(kpi, 'ThresholdHit');

    emitConfigLedger({
      scenario: 'CFG-03',
      source: 'multi-trust-credential',
      ledger: {
        kpi_readiness_state: 'gated_until_wired',
      },
      checks: {
        verifier_required_before_ready: true,
        writer_role_required_before_ready: true,
        oracle_wiring_required_before_ready: true,
      },
    });
  });
});

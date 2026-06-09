import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const WRITER_ROLE = ethers.id('KPI_WRITER');
const METRIC_ID = ethers.id('KPI_CREDIT_SCORE');
const PROJECT_ID = ethers.id('PROJECT_ALPHA');
const LEAF_FULL = 123n;

function tokenIdOf(address: string): bigint {
  return BigInt(address);
}

function emitRwaLedger(entry: Record<string, unknown>) {
  if (process.env.RWA_LEDGER_OUTPUT === '1') {
    console.log(`RWA_LEDGER::${JSON.stringify(entry)}`);
  }
}

describe('MultiTrustCredential / KpiRegistry bootstrap', function () {
  it('requires a verifier before proof checks and succeeds after verifier setup', async function () {
    const [admin, holder] = await ethers.getSigners();
    const mtcFactory = await ethers.getContractFactory('MultiTrustCredential');
    const mtc = await upgrades.deployProxy(mtcFactory, [admin.address, []], {
      kind: 'uups',
      initializer: 'initialize',
      unsafeAllow: ['constructor'],
    });
    await mtc.waitForDeployment();

    const verifier = await ethers.deployContract('MockVerifier');

    await mtc.registerMetric(METRIC_ID, 'Credit Score', WRITER_ROLE, true, 0);
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
      mtc.proveMetric(tokenIdOf(holder.address), METRIC_ID, proofA, proofB, proofC, pubSignals)
    ).to.be.revertedWith('need verifier');

    await mtc.updateVerifier(verifier.target);

    await expect(
      mtc.proveMetric(tokenIdOf(holder.address), METRIC_ID, proofA, proofB, proofC, pubSignals)
    ).to.not.be.reverted;
    expect(
      await mtc.proveMetric(tokenIdOf(holder.address), METRIC_ID, proofA, proofB, proofC, pubSignals)
    ).to.equal(true);

    emitRwaLedger({
      scenario: 'CS-04',
      source: 'multi-trust-credential',
      checks: {
        verifier_required_before_ready: true,
      },
    });
  });

  it('requires MTC admin wiring and writer-role grant before KPI pushes can succeed', async function () {
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

    await expect(
      kpi.registerKpi(PROJECT_ID, 'Utilization', WRITER_ROLE, 2, 1, 80, false)
    ).to.be.reverted;

    await mtc.grantRole(await mtc.ADMIN_ROLE(), kpi.target);
    await kpi.registerKpi(PROJECT_ID, 'Utilization', WRITER_ROLE, 2, 1, 80, false);

    const metricId = ethers.keccak256(ethers.solidityPacked(['bytes32', 'string'], [PROJECT_ID, 'Utilization']));

    await mtc.grantRole(WRITER_ROLE, admin.address);
    await mtc.mint(holder.address, {
      metricId,
      value: 75,
      leafFull: 0,
      uri: '',
      expiresAt: 0,
    });

    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId,
        newValue: 81,
        leafFull: 0,
        expiresAt: 0,
      })
    ).to.be.revertedWith('role');

    await mtc.grantRole(WRITER_ROLE, kpi.target);

    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId,
        newValue: 81,
        leafFull: 0,
        expiresAt: 0,
      })
    ).to.emit(kpi, 'ThresholdHit');

    const metric = await mtc.getMetric(tokenIdOf(holder.address), metricId);
    expect(metric[0]).to.equal(81n);

    emitRwaLedger({
      scenario: 'CS-04',
      source: 'kpi-registry',
      checks: {
        writer_role_required_before_ready: true,
      },
    });
  });

  it('emits RWA ledger for CS-04 KPI readiness gate', async function () {
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
    await mtc.registerMetric(METRIC_ID, 'Occupancy', WRITER_ROLE, false, 1);
    await mtc.grantRole(WRITER_ROLE, admin.address);
    await mtc.mint(holder.address, {
      metricId: METRIC_ID,
      value: 92,
      leafFull: 0,
      uri: '',
      expiresAt: 0,
    });

    const unregisteredMetricId = ethers.id('UNREGISTERED_KPI');
    await expect(
      kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
        metricId: unregisteredMetricId,
        newValue: 88,
        leafFull: 0,
        expiresAt: 0,
      })
    ).to.be.revertedWith('not registered');

    emitRwaLedger({
      scenario: 'CS-04',
      source: 'kpi-registry',
      ledger: {
        kpi_readiness_state: 'gated_until_wired',
      },
      checks: {
        unregistered_metric_rejected: true,
      },
    });
  });
});

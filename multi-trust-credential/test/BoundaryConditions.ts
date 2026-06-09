import { expect } from 'chai';
import { ethers, upgrades } from 'hardhat';

const WRITER_ROLE = ethers.id('KPI_WRITER');
const ORACLE_PROJECT_ID = ethers.id('PROJECT_BOUNDARY_2026_03');
const METRIC_ID = ethers.id('BOUNDARY_METRIC');
const COMMITMENT_METRIC_ID = ethers.id('COMMITMENT_METRIC');
const PROOF = ethers.AbiCoder.defaultAbiCoder().encode(
  ['uint256[2]', 'uint256[2][2]', 'uint256[2]'],
  [[0n, 0n], [[0n, 0n], [0n, 0n]], [0n, 0n]]
);

function tokenIdOf(address: string): bigint {
  return BigInt(address);
}

describe('MultiTrustCredential / KpiRegistry boundary coverage', function () {
  async function deployBoundaryFixture() {
    const [admin, oracle, holder, outsider] = await ethers.getSigners();
    const mtcFactory = await ethers.getContractFactory('MultiTrustCredential');
    const kpiFactory = await ethers.getContractFactory('KpiRegistry');
    const verifierFactory = await ethers.getContractFactory('MockPredicateVerifier');

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

    const verifier = await verifierFactory.deploy();
    await verifier.waitForDeployment();

    await kpi.grantRole(await kpi.ORACLE_ROLE(), oracle.address);
    await mtc.grantRole(await mtc.ADMIN_ROLE(), kpi.target);
    await mtc.grantRole(WRITER_ROLE, admin.address);
    await mtc.grantRole(WRITER_ROLE, kpi.target);

    return { admin, oracle, holder, outsider, mtc, kpi, verifier };
  }

  it('rejects KPI registration boundary mistakes and suppresses threshold hits for commitment metrics', async function () {
    const { oracle, holder, mtc, kpi } = await deployBoundaryFixture();

    await expect(kpi.registerKpi(ORACLE_PROJECT_ID, '', WRITER_ROLE, 2, 1, 100, false)).to.be.revertedWith('label empty');
    await expect(kpi.registerKpi(ORACLE_PROJECT_ID, 'BadMask', WRITER_ROLE, 2, 8, 100, false)).to.be.revertedWith('bad mask');
    await expect(kpi.registerKpi(ORACLE_PROJECT_ID, 'ZeroDecimals', WRITER_ROLE, 0, 1, 100, false)).to.be.revertedWith('decimals=0');

    await kpi.registerKpi(ORACLE_PROJECT_ID, 'Commitment', WRITER_ROLE, 2, 1, 100, true);
    await expect(kpi.registerKpi(ORACLE_PROJECT_ID, 'Commitment', WRITER_ROLE, 2, 1, 100, true)).to.be.revertedWith('exists');

    const metricId = ethers.keccak256(ethers.solidityPacked(['bytes32', 'string'], [ORACLE_PROJECT_ID, 'Commitment']));
    await mtc.mint(holder.address, {
      metricId,
      value: 0,
      leafFull: 777n,
      uri: '',
      expiresAt: 0,
    });

    const tx = await kpi.connect(oracle).pushKpiValue(tokenIdOf(holder.address), {
      metricId,
      newValue: 0,
      leafFull: 888n,
      expiresAt: 0,
    });
    const receipt = await tx.wait();
    const thresholdEvents = (receipt?.logs ?? []).flatMap((log) => {
      try {
        const parsed = kpi.interface.parseLog({ topics: [...log.topics], data: log.data });
        return parsed?.name === 'ThresholdHit' ? [parsed] : [];
      } catch {
        return [];
      }
    });

    expect(thresholdEvents).to.have.length(0);
    expect(await kpi.latestTimestamp(metricId)).to.be.gt(0n);
  });

  it('rejects unsafe predicate profiles and stale predicate proofs', async function () {
    const { admin, holder, mtc, verifier } = await deployBoundaryFixture();
    const tokenId = tokenIdOf(holder.address);

    await mtc.registerMetric(METRIC_ID, 'Boundary Metric', WRITER_ROLE, false, 1);
    await mtc.mint(holder.address, {
      metricId: METRIC_ID,
      value: 10,
      leafFull: 555n,
      uri: '',
      expiresAt: 0,
    });

    await expect(
      mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_RANGE(), await verifier.getAddress(), 7, 1, 3, 0, false, false)
    ).to.be.revertedWith('unsupported signalsLen');

    await expect(
      mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_RANGE(), admin.address, 6, 1, 3, 0, false, false)
    ).to.be.revertedWith('verifier not contract');

    await expect(
      mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_RANGE(), await verifier.getAddress(), 6, 6, 3, 0, false, false)
    ).to.be.revertedWith('bad anchorIndex');

    await expect(
      mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_DELTA(), await verifier.getAddress(), 8, 1, 3, 6, false, false)
    ).to.be.revertedWith('delta needs epochCheck');

    await mtc.setPredicateAllowed(METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), true);
    await mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), await verifier.getAddress(), 6, 1, 3, 0, false, true);

    const allowlistSignals = [0n, 555n, 77n, tokenId, 0n, 0n];
    await expect(
      mtc.provePredicate(tokenId, METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), PROOF, allowlistSignals)
    ).to.be.revertedWith('mask not zero');

    await mtc.setCompareMask(METRIC_ID, 0);
    expect(
      await mtc.provePredicate(tokenId, METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), PROOF, allowlistSignals)
    ).to.equal(true);

    await expect(mtc.setPredicateEpoch(METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), 1)).to.be.revertedWith('epochCheck disabled');

    await mtc.setPredicateAllowed(METRIC_ID, await mtc.PREDICATE_RANGE(), true);
    await mtc.setPredicateProfile(METRIC_ID, await mtc.PREDICATE_RANGE(), await verifier.getAddress(), 8, 1, 3, 6, true, false);
    await mtc.setPredicateEpoch(METRIC_ID, await mtc.PREDICATE_RANGE(), 9);

    const staleSignals = [0n, 555n, 77n, tokenId, 0n, 0n, 8n, 0n];
    await expect(
      mtc.provePredicate(tokenId, METRIC_ID, await mtc.PREDICATE_RANGE(), PROOF, staleSignals)
    ).to.be.revertedWith('bad epoch');

    const validSignals = [0n, 555n, 77n, tokenId, 0n, 0n, 9n, 0n];
    await verifier.setResult(false);
    await expect(
      mtc.provePredicate(tokenId, METRIC_ID, await mtc.PREDICATE_RANGE(), PROOF, validSignals)
    ).to.be.revertedWith('proof fail');

    await verifier.setResult(true);
    expect(await mtc.provePredicate(tokenId, METRIC_ID, await mtc.PREDICATE_RANGE(), PROOF, validSignals)).to.equal(true);
  });

  it('rejects expired and revoked metrics during predicate verification', async function () {
    const { holder, mtc, verifier } = await deployBoundaryFixture();
    const tokenId = tokenIdOf(holder.address);

    await mtc.registerMetric(COMMITMENT_METRIC_ID, 'Expiring Commitment', WRITER_ROLE, true, 0);
    const now = BigInt((await ethers.provider.getBlock('latest'))!.timestamp);
    await mtc.mint(holder.address, {
      metricId: COMMITMENT_METRIC_ID,
      value: 0,
      leafFull: 909n,
      uri: '',
      expiresAt: Number(now + 30n),
    });

    await mtc.setPredicateAllowed(COMMITMENT_METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), true);
    await mtc.setPredicateProfile(COMMITMENT_METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), await verifier.getAddress(), 6, 1, 3, 0, false, true);

    const signals = [0n, 909n, 77n, tokenId, 0n, 0n];
    expect(
      await mtc.provePredicate(tokenId, COMMITMENT_METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), PROOF, signals)
    ).to.equal(true);

    await ethers.provider.send('evm_increaseTime', [31]);
    await ethers.provider.send('evm_mine', []);
    await expect(
      mtc.provePredicate(tokenId, COMMITMENT_METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), PROOF, signals)
    ).to.be.revertedWith('metric expired');

    await mtc.updateMetric(tokenId, {
      metricId: COMMITMENT_METRIC_ID,
      newValue: 0,
      leafFull: 909n,
      expiresAt: 0,
    });
    await mtc.revokeMetric(tokenId, COMMITMENT_METRIC_ID);

    await expect(
      mtc.provePredicate(tokenId, COMMITMENT_METRIC_ID, await mtc.PREDICATE_ALLOWLIST(), PROOF, signals)
    ).to.be.revertedWith('revoked');
  });
});

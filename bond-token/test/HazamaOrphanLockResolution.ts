import { expect } from 'chai';
import { ethers } from 'hardhat';
import { Interface } from 'ethers';
import { buildOrphanResolutionBatch } from '../scripts/prepare-hazama-orphan-lock-resolution';

describe('HAZAMA orphan lock resolution plan', function () {
  const manager = '0x0000000000000000000000000000000000000011';
  const timelock = '0x0000000000000000000000000000000000000012';
  const orderKey = ethers.id('orphan-order');
  const evidenceHash = ethers.id('incident-evidence');

  it('grants, uses, and revokes a temporary release role atomically', function () {
    const batch = buildOrphanResolutionBatch({
      lockManager: manager,
      timelock,
      orderKey,
      incidentId: 'INCIDENT-2026-0001',
      evidenceHash,
      minDelay: 86400n,
    });
    const managerInterface = new Interface([
      'function grantRole(bytes32 role,address account)',
      'function release(bytes32 orderId,bytes32 reasonCode)',
      'function revokeRole(bytes32 role,address account)',
    ]);
    const grant = managerInterface.decodeFunctionData('grantRole', batch.payloads[0]);
    const release = managerInterface.decodeFunctionData('release', batch.payloads[1]);
    const revoke = managerInterface.decodeFunctionData('revokeRole', batch.payloads[2]);

    expect(batch.targets).to.deep.equal([manager, manager, manager]);
    expect(batch.values).to.deep.equal([0n, 0n, 0n]);
    expect(grant[0]).to.equal(ethers.id('RELEASER_ROLE'));
    expect(grant[1]).to.equal(timelock);
    expect(release[0]).to.equal(orderKey);
    expect(release[1]).to.equal(batch.reasonCode);
    expect(revoke[0]).to.equal(ethers.id('RELEASER_ROLE'));
    expect(revoke[1]).to.equal(timelock);
    expect(batch.operationId).to.match(/^0x[0-9a-f]{64}$/);
  });

  it('binds the operation to incident evidence', function () {
    const first = buildOrphanResolutionBatch({
      lockManager: manager,
      timelock,
      orderKey,
      incidentId: 'INCIDENT-2026-0001',
      evidenceHash,
      minDelay: 86400n,
    });
    const changed = buildOrphanResolutionBatch({
      lockManager: manager,
      timelock,
      orderKey,
      incidentId: 'INCIDENT-2026-0001',
      evidenceHash: ethers.id('different-evidence'),
      minDelay: 86400n,
    });

    expect(changed.reasonCode).not.to.equal(first.reasonCode);
    expect(changed.operationId).not.to.equal(first.operationId);
    expect(changed.scheduleCalldata).not.to.equal(first.scheduleCalldata);
    expect(changed.executeCalldata).not.to.equal(first.executeCalldata);
  });

  it('matches the TimelockController operation hash', async function () {
    const [proposer] = await ethers.getSigners();
    const factory = await ethers.getContractFactory('HazamaGovernanceTimelock');
    const deployed = await factory.deploy(
      86400,
      [proposer.address],
      [ethers.ZeroAddress],
      ethers.ZeroAddress,
    );
    await deployed.waitForDeployment();
    const deployedAddress = await deployed.getAddress();
    const batch = buildOrphanResolutionBatch({
      lockManager: manager,
      timelock: deployedAddress,
      orderKey,
      incidentId: 'INCIDENT-2026-0001',
      evidenceHash,
      minDelay: 86400n,
    });

    expect(await deployed.hashOperationBatch(
      batch.targets,
      batch.values,
      batch.payloads,
      batch.predecessor,
      batch.salt,
    )).to.equal(batch.operationId);
  });
});

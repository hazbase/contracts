import { ethers } from 'hardhat';

function csv(name: string): string[] {
  const value = process.env[name]?.trim();
  return value ? value.split(',').map((item) => item.trim()).filter(Boolean) : [];
}

function positiveInteger(name: string): bigint {
  const value = process.env[name]?.trim();
  if (!value || !/^\d+$/.test(value)) throw new Error(`${name} must be an explicit positive integer`);
  const parsed = BigInt(value);
  if (parsed <= 0n) throw new Error(`${name} must be greater than zero`);
  return parsed;
}

function address(name: string): string {
  const value = process.env[name]?.trim();
  if (!value || !ethers.isAddress(value)) throw new Error(`${name} must be an EVM address`);
  return ethers.getAddress(value);
}

async function main() {
  const governanceMultisig = address('HAZAMA_GOVERNANCE_MULTISIG_ADDRESS');
  const emergencyMultisig = address('HAZAMA_EMERGENCY_MULTISIG_ADDRESS');
  const minDelay = positiveInteger('HAZAMA_TIMELOCK_DELAY_SECONDS');
  const executor = process.env.HAZAMA_TIMELOCK_EXECUTOR_ADDRESS?.trim()
    ? address('HAZAMA_TIMELOCK_EXECUTOR_ADDRESS')
    : ethers.ZeroAddress;
  const pauseTargets = csv('HAZAMA_EMERGENCY_PAUSE_TARGETS').map((value) => {
    if (!ethers.isAddress(value)) throw new Error(`Invalid pause target: ${value}`);
    return ethers.getAddress(value);
  });
  const bootstrapAdmin = process.env.HAZAMA_TIMELOCK_BOOTSTRAP_ADMIN?.trim()
    ? address('HAZAMA_TIMELOCK_BOOTSTRAP_ADMIN')
    : ethers.ZeroAddress;
  if (bootstrapAdmin !== ethers.ZeroAddress && process.env.HAZAMA_ALLOW_TEMPORARY_ADMIN !== 'true') {
    throw new Error('A bootstrap admin requires HAZAMA_ALLOW_TEMPORARY_ADMIN=true');
  }

  const timelock = await ethers.deployContract('HazamaGovernanceTimelock', [
    minDelay,
    [governanceMultisig],
    [executor],
    bootstrapAdmin,
  ]);
  await timelock.waitForDeployment();
  const timelockAddress = await timelock.getAddress();

  const pauseGuard = await ethers.deployContract('HazamaEmergencyPauseGuard', [
    timelockAddress,
    emergencyMultisig,
    pauseTargets,
  ]);
  await pauseGuard.waitForDeployment();

  const network = await ethers.provider.getNetwork();
  console.log(JSON.stringify({
    schema: 'hazama-governance-deployment/v1',
    network: network.name,
    chainId: network.chainId.toString(),
    governanceMultisig,
    emergencyMultisig,
    timelock: {
      address: timelockAddress,
      minDelay: minDelay.toString(),
      executor,
      bootstrapAdmin,
      deploymentTx: timelock.deploymentTransaction()?.hash ?? null,
    },
    emergencyPauseGuard: {
      address: await pauseGuard.getAddress(),
      targets: pauseTargets,
      deploymentTx: pauseGuard.deploymentTransaction()?.hash ?? null,
    },
    next: [
      'Run the governance migration script in audit mode.',
      'Grant the exact planned target roles in prepare mode.',
      'Execute and verify a scheduled test operation through the Timelock.',
      'Only then finalize revocation of the legacy admin roles.',
    ],
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

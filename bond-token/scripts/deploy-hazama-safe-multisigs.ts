import { ethers } from 'hardhat';

const safeAbi = [
  'function VERSION() view returns (string)',
  'function getOwners() view returns (address[])',
  'function getThreshold() view returns (uint256)',
  'function setup(address[] _owners,uint256 _threshold,address to,bytes data,address fallbackHandler,address paymentToken,uint256 payment,address payable paymentReceiver)',
];

const proxyFactoryAbi = [
  'event ProxyCreation(address indexed proxy,address singleton)',
  'function proxyCreationCode() view returns (bytes)',
  'function createProxyWithNonce(address _singleton,bytes initializer,uint256 saltNonce) returns (address proxy)',
];

function requiredAddress(name: string): string {
  const value = process.env[name]?.trim();
  if (!value || !ethers.isAddress(value)) throw new Error(`${name} must be an EVM address`);
  return ethers.getAddress(value);
}

function requiredOwners(): string[] {
  const values = process.env.HAZAMA_SAFE_OWNER_ADDRESSES
    ?.split(',')
    .map((value) => value.trim())
    .filter(Boolean) ?? [];
  if (values.length < 2) throw new Error('HAZAMA_SAFE_OWNER_ADDRESSES requires at least two owners');
  const owners = values.map((value) => {
    if (!ethers.isAddress(value)) throw new Error(`Invalid Safe owner: ${value}`);
    return ethers.getAddress(value);
  });
  const unique = new Set(owners.map((value) => value.toLowerCase()));
  if (unique.size !== owners.length) throw new Error('Safe owners must be unique');
  return owners.sort((left, right) => left.toLowerCase().localeCompare(right.toLowerCase()));
}

function requiredThreshold(ownerCount: number): bigint {
  const value = process.env.HAZAMA_SAFE_THRESHOLD?.trim();
  if (!value || !/^\d+$/.test(value)) throw new Error('HAZAMA_SAFE_THRESHOLD must be an integer');
  const threshold = BigInt(value);
  if (threshold === 0n || threshold > BigInt(ownerCount)) {
    throw new Error('HAZAMA_SAFE_THRESHOLD must be between 1 and the owner count');
  }
  return threshold;
}

function saltNonce(label: string): bigint {
  return BigInt(ethers.keccak256(ethers.toUtf8Bytes(label)));
}

async function requireContract(name: string, address: string) {
  if (await ethers.provider.getCode(address) === '0x') {
    throw new Error(`${name} is not deployed: ${address}`);
  }
}

async function verifySafe(address: string, owners: string[], threshold: bigint) {
  const safe = new ethers.Contract(address, safeAbi, ethers.provider);
  const actualOwners = (await safe.getOwners() as string[])
    .map(ethers.getAddress)
    .sort((left, right) => left.toLowerCase().localeCompare(right.toLowerCase()));
  const expectedOwners = [...owners]
    .sort((left, right) => left.toLowerCase().localeCompare(right.toLowerCase()));
  if (JSON.stringify(actualOwners) !== JSON.stringify(expectedOwners)) {
    throw new Error(`Safe owner verification failed for ${address}`);
  }
  if (BigInt(await safe.getThreshold()) !== threshold) {
    throw new Error(`Safe threshold verification failed for ${address}`);
  }
  return String(await safe.VERSION());
}

async function deploySafe(
  name: string,
  singleton: string,
  proxyFactoryAddress: string,
  fallbackHandler: string,
  owners: string[],
  threshold: bigint,
  label: string,
  mode: 'audit' | 'deploy',
) {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error('No deployer signer is configured');
  const proxyFactory = new ethers.Contract(proxyFactoryAddress, proxyFactoryAbi, deployer);
  const safeInterface = new ethers.Interface(safeAbi);
  const initializer = safeInterface.encodeFunctionData('setup', [
    owners,
    threshold,
    ethers.ZeroAddress,
    '0x',
    fallbackHandler,
    ethers.ZeroAddress,
    0n,
    ethers.ZeroAddress,
  ]);
  const nonce = saltNonce(label);
  const proxyCreationCode = String(await proxyFactory.proxyCreationCode());
  const deploymentCode = ethers.concat([
    proxyCreationCode,
    ethers.zeroPadValue(singleton, 32),
  ]);
  const salt = ethers.keccak256(ethers.concat([
    ethers.keccak256(initializer),
    ethers.zeroPadValue(ethers.toBeHex(nonce), 32),
  ]));
  const predictedAddress = ethers.getCreate2Address(
    proxyFactoryAddress,
    salt,
    ethers.keccak256(deploymentCode),
  );

  let deploymentTx: string | null = null;
  const existed = await ethers.provider.getCode(predictedAddress) !== '0x';
  if (!existed && mode === 'deploy') {
    const tx = await proxyFactory.createProxyWithNonce(singleton, initializer, nonce);
    const receipt = await tx.wait();
    deploymentTx = receipt?.hash ?? tx.hash;
    if (await ethers.provider.getCode(predictedAddress) === '0x') {
      throw new Error(`${name} Safe deployment did not create the predicted proxy`);
    }
  }

  const deployed = await ethers.provider.getCode(predictedAddress) !== '0x';
  const version = deployed
    ? await verifySafe(predictedAddress, owners, threshold)
    : null;

  return {
    name,
    address: ethers.getAddress(predictedAddress),
    version,
    owners,
    threshold: threshold.toString(),
    saltLabel: label,
    saltNonce: nonce.toString(),
    deploymentTx,
    deployed,
    reused: existed,
  };
}

async function main() {
  const singleton = requiredAddress('HAZAMA_SAFE_SINGLETON_ADDRESS');
  const proxyFactory = requiredAddress('HAZAMA_SAFE_PROXY_FACTORY_ADDRESS');
  const fallbackHandler = requiredAddress('HAZAMA_SAFE_FALLBACK_HANDLER_ADDRESS');
  const owners = requiredOwners();
  const threshold = requiredThreshold(owners.length);
  const mode = process.env.HAZAMA_SAFE_DEPLOY_MODE?.trim() || 'audit';
  if (mode !== 'audit' && mode !== 'deploy') {
    throw new Error('HAZAMA_SAFE_DEPLOY_MODE must be audit or deploy');
  }
  const governanceLabel = process.env.HAZAMA_GOVERNANCE_SAFE_SALT_LABEL?.trim();
  const emergencyLabel = process.env.HAZAMA_EMERGENCY_SAFE_SALT_LABEL?.trim();
  if (!governanceLabel || !emergencyLabel) {
    throw new Error('Both Safe salt labels are required');
  }
  if (governanceLabel === emergencyLabel) throw new Error('Safe salt labels must be different');

  await requireContract('Safe singleton', singleton);
  await requireContract('Safe proxy factory', proxyFactory);
  await requireContract('Safe fallback handler', fallbackHandler);
  const network = await ethers.provider.getNetwork();
  const governance = await deploySafe(
    'HAZAMA Governance Safe',
    singleton,
    proxyFactory,
    fallbackHandler,
    owners,
    threshold,
    governanceLabel,
    mode,
  );
  const emergency = await deploySafe(
    'HAZAMA Emergency Safe',
    singleton,
    proxyFactory,
    fallbackHandler,
    owners,
    threshold,
    emergencyLabel,
    mode,
  );

  console.log(JSON.stringify({
    schema: 'hazama-safe-multisig-deployment/v1',
    mode,
    chainId: network.chainId.toString(),
    singleton,
    proxyFactory,
    fallbackHandler,
    governance,
    emergency,
  }, null, 2));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

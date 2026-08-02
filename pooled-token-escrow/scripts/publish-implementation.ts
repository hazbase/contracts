import { ethers } from "hardhat";

const FACTORY_ABI = [
  "function setImplementationWithPolicy(bytes32 contractType,address impl,bool cloneable,bool initRequired,bytes4 initSelector)",
  "function getLatestImplementation(address owner,bytes32 contractType) view returns (address)",
];

function requiredAddress(name: string): string {
  const value = String(process.env[name] ?? "").trim();
  if (!value) throw new Error(`${name} is required`);
  return ethers.getAddress(value);
}

function optionalAddress(name: string): string | null {
  const value = String(process.env[name] ?? "").trim();
  return value ? ethers.getAddress(value) : null;
}

async function main() {
  const [publisher] = await ethers.getSigners();
  const factoryAddress = requiredAddress("CONTRACT_FACTORY_ADDRESS");
  const escrowFactory = await ethers.getContractFactory("PooledTokenEscrow");
  const contractType = ethers.id("PooledTokenEscrow");
  const initializerSelector = escrowFactory.interface.getFunction("initialize")!.selector;
  const factory = new ethers.Contract(factoryAddress, FACTORY_ABI, publisher);

  let implementationAddress = optionalAddress("POOLED_TOKEN_ESCROW_IMPLEMENTATION_ADDRESS");
  if (!implementationAddress) {
    const implementation = await escrowFactory.deploy();
    await implementation.waitForDeployment();
    implementationAddress = await implementation.getAddress();
  } else if ((await ethers.provider.getCode(implementationAddress)) === "0x") {
    throw new Error("POOLED_TOKEN_ESCROW_IMPLEMENTATION_ADDRESS does not contain contract code");
  }

  await factory.setImplementationWithPolicy.staticCall(
    contractType,
    implementationAddress,
    true,
    true,
    initializerSelector,
  );
  const transaction = await factory.setImplementationWithPolicy(
    contractType,
    implementationAddress,
    true,
    true,
    initializerSelector,
  );
  const receipt = await transaction.wait();
  const registered = ethers.getAddress(
    await factory.getLatestImplementation(publisher.address, contractType),
  );
  if (registered !== ethers.getAddress(implementationAddress)) {
    throw new Error("Factory implementation verification failed");
  }

  const network = await ethers.provider.getNetwork();
  console.log(JSON.stringify({
    chainId: network.chainId.toString(),
    factory: factoryAddress,
    implementationOwner: publisher.address,
    implementation: registered,
    contractType,
    initializerSelector,
    registrationTransactionHash: receipt?.hash ?? transaction.hash,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

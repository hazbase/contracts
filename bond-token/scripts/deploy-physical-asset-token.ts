import { ethers } from "hardhat";

const factoryAbi = [
  "function setImplementation(bytes32 contractType,address impl)",
  "function setImplementationWithPolicy(bytes32 contractType,address impl,bool cloneable,bool initRequired,bytes4 initSelector)",
  "function deployContract(address implementationOwner,bytes32 contractType,bytes initData) returns (address proxy)",
  "event ContractDeployed(address indexed implementationOwner,bytes32 indexed contractType,address indexed proxy,address deployer)",
];

function requiredAddress(name: string) {
  const value = String(process.env[name] ?? "").trim();
  if (!value) throw new Error(`${name} is required`);
  return ethers.getAddress(value);
}

function optionalAddress(name: string) {
  const value = String(process.env[name] ?? "").trim();
  return value ? ethers.getAddress(value) : ethers.ZeroAddress;
}

function requiredText(name: string) {
  const value = String(process.env[name] ?? "").trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function main() {
  const [signer] = await ethers.getSigners();
  const factoryAddress = requiredAddress("CONTRACT_FACTORY_ADDRESS");
  const publishImplementation = String(process.env.PUBLISH_IMPLEMENTATION ?? "true").toLowerCase() === "true";
  const tokenFactory = await ethers.getContractFactory("PhysicalAssetToken");
  const contractType = ethers.id("PhysicalAssetToken");
  const initializerSelector = tokenFactory.interface.getFunction("initialize")!.selector;
  const factory = new ethers.Contract(factoryAddress, factoryAbi, signer);

  let implementationAddress = optionalAddress("PHYSICAL_ASSET_IMPLEMENTATION_ADDRESS");
  let registrationMode: "policy" | "legacy" | null = null;
  let implementationOwner = String(process.env.IMPLEMENTATION_OWNER ?? "").trim();
  if (publishImplementation) {
    if (implementationAddress === ethers.ZeroAddress) {
      const implementation = await tokenFactory.deploy();
      await implementation.waitForDeployment();
      implementationAddress = await implementation.getAddress();
    } else if ((await ethers.provider.getCode(implementationAddress)) === "0x") {
      throw new Error("PHYSICAL_ASSET_IMPLEMENTATION_ADDRESS does not contain contract code");
    }
    implementationOwner = signer.address;
    let registration;
    try {
      await factory.setImplementationWithPolicy.staticCall(
        contractType,
        implementationAddress,
        true,
        true,
        initializerSelector,
      );
      registration = await factory.setImplementationWithPolicy(
        contractType,
        implementationAddress,
        true,
        true,
        initializerSelector,
      );
      registrationMode = "policy";
    } catch {
      registration = await factory.setImplementation(contractType, implementationAddress);
      registrationMode = "legacy";
    }
    await registration.wait();
  } else {
    implementationOwner = ethers.getAddress(requiredText("IMPLEMENTATION_OWNER"));
    implementationAddress = ethers.ZeroAddress;
  }

  const tenantKeyInput = requiredText("PHYSICAL_ASSET_TENANT_KEY");
  const tenantKey = /^0x[0-9a-fA-F]{64}$/u.test(tenantKeyInput)
    ? tenantKeyInput.toLowerCase()
    : ethers.id(tenantKeyInput);
  const initData = tokenFactory.interface.encodeFunctionData("initialize", [
    requiredText("PHYSICAL_ASSET_TOKEN_NAME"),
    requiredText("PHYSICAL_ASSET_TOKEN_SYMBOL"),
    String(process.env.PHYSICAL_ASSET_BASE_URI ?? "").trim(),
    tenantKey,
    requiredAddress("PHYSICAL_ASSET_ADMIN"),
    requiredAddress("PHYSICAL_ASSET_ISSUER"),
    requiredAddress("PHYSICAL_ASSET_GUARDIAN"),
    requiredAddress("PHYSICAL_ASSET_REDEEMER"),
    optionalAddress("PHYSICAL_ASSET_TRANSFER_POLICY"),
  ]);
  const deployment = await factory.deployContract(implementationOwner, contractType, initData);
  const receipt = await deployment.wait();
  const parsed = receipt.logs
    .map((log: { topics: string[]; data: string }) => {
      try {
        return factory.interface.parseLog(log);
      } catch {
        return null;
      }
    })
    .find((event: { name?: string } | null) => event?.name === "ContractDeployed");
  const tokenAddress = parsed?.args?.proxy ? ethers.getAddress(String(parsed.args.proxy)) : null;
  if (!tokenAddress || (await ethers.provider.getCode(tokenAddress)) === "0x") {
    throw new Error("PhysicalAssetToken clone deployment could not be verified");
  }

  const token = tokenFactory.attach(tokenAddress);
  if ((await token.tenantKey()).toLowerCase() !== tenantKey.toLowerCase()) {
    throw new Error("PhysicalAssetToken tenant key verification failed");
  }
  console.log(JSON.stringify({
    network: await ethers.provider.getNetwork().then((network) => network.name),
    chainId: (await ethers.provider.getNetwork()).chainId.toString(),
    contractType,
    implementationOwner,
    implementationAddress: implementationAddress === ethers.ZeroAddress ? null : implementationAddress,
    registrationMode,
    physicalAssetToken: tokenAddress,
    tenantKey,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

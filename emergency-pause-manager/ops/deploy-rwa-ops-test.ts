import { ethers, upgrades } from "hardhat";

function addresses(value: string | undefined) {
  if (!value?.trim()) return [];
  return value.split(",").map((entry) => ethers.getAddress(entry.trim()));
}

async function main() {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 11155111) throw new Error(`Expected Sepolia (11155111), received ${chainId}`);

  const [deployer] = await ethers.getSigners();
  const admin = ethers.getAddress(process.env.ADMIN_ADDRESS?.trim() || deployer.address);
  const forwarders = addresses(process.env.TRUSTED_FORWARDERS);
  const factory = await ethers.getContractFactory("EmergencyPauseManager");
  await upgrades.validateImplementation(factory, { kind: "uups" });

  if (process.env.CONFIRM_RWA_OPS_TEST_DEPLOYMENT !== "sepolia") {
    console.log(JSON.stringify({
      mode: "preflight",
      mutation: false,
      contract: "EmergencyPauseManager",
      network: "sepolia",
      chainId,
      deployer: deployer.address,
      deployerBalanceWei: (await ethers.provider.getBalance(deployer.address)).toString(),
      admin,
      forwarders,
      nextStep: "Set CONFIRM_RWA_OPS_TEST_DEPLOYMENT=sepolia only after deployment approval.",
    }, null, 2));
    return;
  }

  const proxy = await upgrades.deployProxy(factory, [admin, forwarders], {
    initializer: "initialize",
    kind: "uups",
  });
  await proxy.waitForDeployment();

  const proxyAddress = await proxy.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  const pauserRole = await proxy.PAUSER_ROLE();
  if (!(await proxy.hasRole(pauserRole, admin))) throw new Error("Pause manager admin is missing PAUSER_ROLE");

  console.log(JSON.stringify({
    contract: "EmergencyPauseManager",
    network: "sepolia",
    chainId,
    proxyAddress,
    implementationAddress,
    deployer: deployer.address,
    admin,
    forwarders,
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

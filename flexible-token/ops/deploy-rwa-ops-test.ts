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
  const treasury = ethers.getAddress(process.env.TREASURY_ADDRESS?.trim() || admin);
  const name = process.env.TOKEN_NAME?.trim() || "hazBase Test JPY";
  const symbol = process.env.TOKEN_SYMBOL?.trim() || "hJPY";
  const decimals = Number(process.env.TOKEN_DECIMALS ?? "0");
  const initialSupply = BigInt(process.env.TOKEN_INITIAL_SUPPLY ?? "0");
  const cap = BigInt(process.env.TOKEN_CAP ?? "1000000000000");
  const forwarders = addresses(process.env.TRUSTED_FORWARDERS);

  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18) throw new Error("TOKEN_DECIMALS must be 0..18");
  if (cap !== 0n && cap < initialSupply) throw new Error("TOKEN_CAP must cover TOKEN_INITIAL_SUPPLY");

  const factory = await ethers.getContractFactory("FlexibleToken");
  await upgrades.validateImplementation(factory, { kind: "uups" });

  if (process.env.CONFIRM_RWA_OPS_TEST_DEPLOYMENT !== "sepolia") {
    console.log(JSON.stringify({
      mode: "preflight",
      mutation: false,
      contract: "FlexibleToken",
      network: "sepolia",
      chainId,
      deployer: deployer.address,
      deployerBalanceWei: (await ethers.provider.getBalance(deployer.address)).toString(),
      admin,
      treasury,
      name,
      symbol,
      decimals,
      initialSupply: initialSupply.toString(),
      cap: cap.toString(),
      nextStep: "Set CONFIRM_RWA_OPS_TEST_DEPLOYMENT=sepolia only after deployment approval.",
    }, null, 2));
    return;
  }

  const proxy = await upgrades.deployProxy(
    factory,
    [name, symbol, treasury, initialSupply, cap, decimals, true, admin, forwarders],
    { initializer: "initialize", kind: "uups" },
  );
  await proxy.waitForDeployment();

  const proxyAddress = await proxy.getAddress();
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
  if ((await proxy.name()) !== name || (await proxy.symbol()) !== symbol || Number(await proxy.decimals()) !== decimals) {
    throw new Error("Deployed payment token metadata verification failed");
  }

  console.log(JSON.stringify({
    contract: "FlexibleToken",
    network: "sepolia",
    chainId,
    proxyAddress,
    implementationAddress,
    deployer: deployer.address,
    admin,
    treasury,
    name,
    symbol,
    decimals,
    initialSupply: initialSupply.toString(),
    cap: cap.toString(),
  }, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

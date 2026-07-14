import { ethers } from "hardhat";

type WiringTask = {
  key: string;
  run: () => Promise<unknown>;
};

function requiredAddress(name: string) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return ethers.getAddress(value);
}

async function main() {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  if (chainId !== 11155111) throw new Error(`Expected Sepolia (11155111), received ${chainId}`);

  const [admin] = await ethers.getSigners();
  const bondTokenAddress = requiredAddress("BOND_TOKEN_ADDRESS");
  const debtManagerAddress = requiredAddress("DEBT_MANAGER_ADDRESS");
  const pauseManagerAddress = requiredAddress("PAUSE_MANAGER_ADDRESS");
  const operatorAddress = requiredAddress("OPERATOR_SMART_ACCOUNT_ADDRESS");
  const guardianAddress = ethers.getAddress(process.env.PAUSE_GUARDIAN_ADDRESS?.trim() || operatorAddress);
  const governorAddress = ethers.getAddress(process.env.PAUSE_GOVERNOR_ADDRESS?.trim() || operatorAddress);

  for (const [name, address] of Object.entries({
    bondToken: bondTokenAddress,
    debtManager: debtManagerAddress,
    pauseManager: pauseManagerAddress,
  })) {
    if ((await ethers.provider.getCode(address)) === "0x") throw new Error(`${name} has no deployed code at ${address}`);
  }

  const accessAbi = [
    "function MINTER_ROLE() view returns (bytes32)",
    "function PAUSER_ROLE() view returns (bytes32)",
    "function hasRole(bytes32 role,address account) view returns (bool)",
    "function grantRole(bytes32 role,address account)",
  ];
  const bondToken = new ethers.Contract(bondTokenAddress, accessAbi, admin);
  const debtManager = new ethers.Contract(debtManagerAddress, accessAbi, admin);
  const pauseManager = new ethers.Contract(pauseManagerAddress, [
    ...accessAbi,
    "function GUARDIAN_ROLE() view returns (bytes32)",
    "function GOVERNOR_ROLE() view returns (bytes32)",
    "function getTargets() view returns (address[])",
    "function registerPausable(address target)",
  ], admin);

  const bondMinterRole = await bondToken.MINTER_ROLE();
  const bondPauserRole = await bondToken.PAUSER_ROLE();
  const debtMinterRole = await debtManager.MINTER_ROLE();
  const debtPauserRole = await debtManager.PAUSER_ROLE();
  const guardianRole = await pauseManager.GUARDIAN_ROLE();
  const governorRole = await pauseManager.GOVERNOR_ROLE();
  const registeredTargets = new Set((await pauseManager.getTargets()).map((value: string) => value.toLowerCase()));
  const tasks: WiringTask[] = [];

  if (!(await debtManager.hasRole(debtMinterRole, operatorAddress))) {
    tasks.push({
      key: "grant DebtManager MINTER_ROLE to the operator smart account",
      run: () => debtManager.grantRole(debtMinterRole, operatorAddress),
    });
  }
  if (!(await bondToken.hasRole(bondMinterRole, debtManagerAddress))) {
    tasks.push({
      key: "grant BondToken MINTER_ROLE to DebtManager for snapshot and burn",
      run: () => bondToken.grantRole(bondMinterRole, debtManagerAddress),
    });
  }
  if (!(await bondToken.hasRole(bondPauserRole, pauseManagerAddress))) {
    tasks.push({
      key: "grant BondToken PAUSER_ROLE to PauseManager",
      run: () => bondToken.grantRole(bondPauserRole, pauseManagerAddress),
    });
  }
  if (!(await debtManager.hasRole(debtPauserRole, pauseManagerAddress))) {
    tasks.push({
      key: "grant DebtManager PAUSER_ROLE to PauseManager",
      run: () => debtManager.grantRole(debtPauserRole, pauseManagerAddress),
    });
  }
  if (!(await pauseManager.hasRole(guardianRole, guardianAddress))) {
    tasks.push({
      key: "grant PauseManager GUARDIAN_ROLE",
      run: () => pauseManager.grantRole(guardianRole, guardianAddress),
    });
  }
  if (!(await pauseManager.hasRole(governorRole, governorAddress))) {
    tasks.push({
      key: "grant PauseManager GOVERNOR_ROLE",
      run: () => pauseManager.grantRole(governorRole, governorAddress),
    });
  }
  for (const target of [bondTokenAddress, debtManagerAddress]) {
    if (!registeredTargets.has(target.toLowerCase())) {
      tasks.push({
        key: `register pausable target ${target}`,
        run: () => pauseManager.registerPausable(target),
      });
    }
  }

  const plan = {
    mode: process.env.CONFIRM_RWA_OPS_TEST_ROLE_WIRING === "sepolia" ? "apply" : "preflight",
    mutation: process.env.CONFIRM_RWA_OPS_TEST_ROLE_WIRING === "sepolia",
    chainId,
    admin: admin.address,
    bondTokenAddress,
    debtManagerAddress,
    pauseManagerAddress,
    operatorAddress,
    guardianAddress,
    governorAddress,
    sharedPaymentTokenPauseDelegated: false,
    pendingTasks: tasks.map((task) => task.key),
  };
  console.log(JSON.stringify(plan, null, 2));

  if (process.env.CONFIRM_RWA_OPS_TEST_ROLE_WIRING !== "sepolia") return;
  for (const task of tasks) {
    const tx = await task.run() as { wait: () => Promise<unknown>; hash?: string };
    console.log(JSON.stringify({ task: task.key, txHash: tx.hash ?? null }));
    await tx.wait();
  }
  console.log(JSON.stringify({ status: "complete", appliedTaskCount: tasks.length }));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

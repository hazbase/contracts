/**
 * Hardhat deploy script template
 *
 * Usage examples
 * ------------------------------------------------------------------
 * On-chain (default signer):
 *   PRIVATE_KEY=0x... npx hardhat run scripts/deploy.ts --network sepolia
 *
 * With constructor arguments:
 *   CONSTRUCTOR_ARGS='["Alice",42]' npm run deploy
 *
 * With proxy initializer:
 *   INITIALIZER=initialize \
 *   INIT_ARGS='["Bob",123]' \
 *   npm run deploy
 *
 * Environment variables
 * ------------------------------------------------------------------
 * CONTRACT_NAME      Name of the contract to deploy      (default: Example)
 * CONSTRUCTOR_ARGS   JSON array for constructor args     (optional)
 * INITIALIZER        Initializer function name           (optional)
 * INIT_ARGS          JSON array for initializer args     (optional)
 */

import { ethers, upgrades } from 'hardhat';

async function main() {
  /* ---------------------------------------------------------------- */
  /*  Load env / defaults                                             */
  /* ---------------------------------------------------------------- */
  const CONTRACT_NAME   = process.env.CONTRACT_NAME ?? 'Example';
  const ctorArgs: unknown[] = process.env.CONSTRUCTOR_ARGS
    ? JSON.parse(process.env.CONSTRUCTOR_ARGS)
    : [];

  const INITIALIZER     = process.env.INITIALIZER;        // e.g. "initialize"
  const initArgs: unknown[] = process.env.INIT_ARGS
    ? JSON.parse(process.env.INIT_ARGS)
    : [];

  /* ---------------------------------------------------------------- */
  /*  Get ContractFactory                                             */
  /* ---------------------------------------------------------------- */
  const Factory = await ethers.getContractFactory(CONTRACT_NAME);

  /* ---------------------------------------------------------------- */
  /*  Deploy                                                          */
  /* ---------------------------------------------------------------- */
  let address: string;
  if (INITIALIZER) {
    // Deploy as UUPS proxy
    const proxy = await upgrades.deployProxy(
      Factory,
      initArgs,
      { initializer: INITIALIZER }
    );
    await proxy.waitForDeployment();
    address = await proxy.getAddress();
  } else {
    // Direct deployment
    const instance = await Factory.deploy(...ctorArgs);
    await instance.waitForDeployment();
    address = await instance.getAddress();
  }

  console.log(`✅ ${CONTRACT_NAME} deployed at`, address);
}

/* ------------------------------------------------------------------ */
main()
  .then(() => process.exit(0))
  .catch((err: any) => {
    console.error(err);
    process.exit(1);
  });

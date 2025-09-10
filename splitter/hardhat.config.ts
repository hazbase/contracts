import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import "@openzeppelin/hardhat-upgrades";
import "hardhat-contract-sizer";

const config: HardhatUserConfig = {
  solidity: {
    compilers: [{ version: '0.8.22' }],
    version: "0.8.22",
    settings: {
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 50
      }
    }
  },
  paths: { sources: './contracts', tests: './test', cache: './cache', artifacts: './artifacts' },
  networks: {
    sepolia: {
      url: process.env.RPC_URL_11155111 || process.env.RPC_URL || '',
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    }
  },
  contractSizer: {
    runOnCompile: true,
    strict: true,
    only: ['Splitter'],
  }
};

export default config;

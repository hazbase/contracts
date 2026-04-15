// hardhat.config.ts
import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';

function resolveRpcUrl(chainId: number, aliases: string[] = []) {
  const envKeys = [`RPC_URL_${chainId}`, ...aliases, 'RPC_URL'];
  for (const key of envKeys) {
    const value = process.env[key];
    if (value && value.trim()) return value;
  }
  return '';
}


const config: HardhatUserConfig = {
  // 複数バージョンを compiler に登録
  solidity: {
    compilers: [
      {
        version: '0.8.22',
        settings: {
          optimizer: { enabled: true, runs: 200 }
        }
      },
      {
        version: '0.8.20',
        settings: {
          optimizer: { enabled: true, runs: 200 }
        }
      }
    ]
  },
  paths: {
    sources: './contracts',
    tests:   './test',
    cache:   './cache',
    artifacts: './artifacts'
  },
  networks: {
    mainnet: {
      url: resolveRpcUrl(1, ['ETHEREUM_RPC_URL', 'MAINNET_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    sepolia: {
      url: resolveRpcUrl(11155111, ['SEPOLIA_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    polygon: {
      url: resolveRpcUrl(137, ['POLYGON_RPC_URL', 'MATIC_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    amoy: {
      url: resolveRpcUrl(80002, ['AMOY_RPC_URL', 'POLYGON_AMOY_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    avalanche: {
      url: resolveRpcUrl(43114, ['AVALANCHE_RPC_URL', 'AVAX_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    fuji: {
      url: resolveRpcUrl(43113, ['FUJI_RPC_URL', 'AVALANCHE_FUJI_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    bnb: {
      url: resolveRpcUrl(56, ['BNB_RPC_URL', 'BSC_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    bscTestnet: {
      url: resolveRpcUrl(97, ['BNB_TESTNET_RPC_URL', 'BSC_TESTNET_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    world: {
      url: resolveRpcUrl(480, ['WORLD_RPC_URL', 'WORLDCHAIN_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    },
    worldSepolia: {
      url: resolveRpcUrl(4801, ['WORLD_SEPOLIA_RPC_URL', 'WORLDCHAIN_SEPOLIA_RPC_URL']),
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    }
  },
};

export default config;

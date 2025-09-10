// hardhat.config.ts
import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';

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
    sepolia: {
      url: process.env.RPC_URL_11155111 || process.env.RPC_URL || '',
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : []
    }
    // 必要なら他チェーンも追加
  }
};

export default config;

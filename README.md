# Token Market Contracts & ZK Circuits

A production-grade suite of modular EVM smart contracts for building compliant token markets.

**License:** Apache-2.0 • **Languages:** Solidity / Circom / TypeScript • **Status:** Open Source

---

## Table of Contents
- [1. Overview](#overview)
- [2. Key Features](#key-features)
- [3. Architecture & Modules](#architecture-modules)
- [4. Contracts Catalog](#contracts-catalog)
- [5. Getting Started](#getting-started)
- [6. Build, Test & Verify](#build-test-verify)
- [7. ZK Circuits (circom/snarkjs)](#zk-circuits)
- [8. Security Model & Operational Guidance](#security-model-operational-guidance)
- [9. Contribution & Commit Signing](#contribution-commit-signing)
- [10. License](#license)
- [11. Acknowledgements & Attribution](#acknowledgements-attribution)
- [12. Disclaimer & Patents](#disclaimer-patents)

---

## 1. Overview <a id="overview"></a>

This repository provides modular, reusable smart contracts and ZK building blocks to create compliant token markets on EVM-compatible chains. It covers token issuance and lifecycle management, a circuit-breaker AMM, governance and staking, ERC-4337 accounts & paymasters, and Groth16 verifiers for Circom circuits. The codebase emphasizes auditability, upgrade safety (timelocks/roles), and interoperability. Licensed under Apache-2.0.

## 2. Key Features <a id="key-features"></a>

- Token issuance & lifecycle: flexible ERC-20, bond-like multi-class tokens, and membership NFTs.
- Market infrastructure: circuit-breaker AMM, factory/router, reserve pools, revenue splitters, strategies.
- Risk & controls: emergency pause, whitelists, role-based access, timelocks, on-chain circuit breakers.
- Governance & staking: governor modules, voting, staking, and reward distribution.
- Accounts & gas: ERC-4337 smart accounts, account factory, verifying paymasters, meta-tx context (EIP-2771).
- ZK support: Circom circuits, Groth16 verifiers (snarkjs), reproducible setup guidance.
- Compliance orientation: KYC/whitelist hooks, upgradeable governance, audit-friendly structure.

## 3. Architecture & Modules <a id="architecture-modules"></a>

The system is decomposed into layers:  
(a) **Asset Layer** (ERC-20/1155/NFT and bond-like instruments),  
(b) **Market Layer** (AMM with risk controls, reserve & routing),  
(c) **Governance Layer** (governors, timelock, staking),  
(d) **Access & Compliance** (roles, whitelists, pause),  
(e) **Accounts & Gas** (ERC-4337), and  
(f) **ZK Layer** (verifiers & circuits).

## 4. Contracts Catalog <a id="contracts-catalog"></a>

- **FlexibleToken.sol** — Flexible ERC-20 token with mint/burn controls and role-based permissions.  
- **BondToken.sol** — Multi-class / tranche-style bond token (ERC-3475-like semantics for lifecycle & tranches).  
- **PrivilegeNFT.sol** — Membership/privilege NFT for gated access and benefits.  
- **PrivilegeEdition.sol** — Editioned/minted privileges; complements PrivilegeNFT.  
- **CircuitBreakerAMM.sol** — AMM with risk controls and circuit-breaker halts to mitigate volatility or illiquidity.  
- **AMMFactory.sol** — Factory contract to deploy and register AMM pools/pairs.  
- **AMMRouter.sol** — Router that orchestrates swaps and liquidity add/remove across pools.  
- **ReservePool.sol** — Reserve management contract to hold backing assets/liquidity for markets or obligations.  
- **Splitter.sol** — Revenue splitter that routes proceeds to multiple destinations based on BPS.  
- **Strategy.sol** — Pluggable strategy interface/implementation for treasury or reserve allocation.  
- **EmergencyPauseManager.sol** — Guardian/owner controlled emergency pause across critical modules.  
- **RolesCommon.sol** — Common roles/constants shared across contracts (e.g., ADMIN/MINTER/PAUSER).  
- **Whitelist.sol** — Allowlist for compliance/KYC gating of sensitive operations.  
- **ERC2771ContextUpgradeable.sol** — Meta-transaction context support for trusted forwarders (EIP-2771).  
- **AccountFactory.sol** — Factory for deploying ERC-4337 compatible smart accounts.  
- **SmartAccount.sol** — Minimal smart account compatible with ERC-4337 entry point flows.  
- **VerifyingPaymaster.sol** — ERC-4337 paymaster verifying ops against policy/signatures.  
- **Verifier.sol** — Groth16 verifier (auto-generated) used to validate ZK proofs on-chain.  
- **MultiTrustCredential.sol** — Credential/attestation mechanism with multiple trust anchors.  
- **KpiRegistry.sol** — Registry to define/update/revoke KPIs/metrics for incentives or slashing logic.  
- **Staking.sol** — Staking and reward distribution mechanics for governance or incentives.  
- **GenericGovernor.sol** — Governor module (OpenZeppelin-style) with proposal & voting.  
- **MetaGovernor.sol** — Meta-governor that can coordinate or aggregate governance across modules.  
- **TimelockController.sol** — Timelock to enforce upgrade delays and transparent operations.  
- **ContractFactory.sol** — Generic factory to deploy controlled instances (e.g., via minimal proxies).  
- **MarketManager.sol** — Coordinator for market lifecycles, listings, or asset onboarding.  
- **AgreementManager.sol** — Agreement/escrow workflows to model bilateral/multilateral commitments.  
- **DebtManager.sol** — Debt instrument primitives including optional put/call mechanisms.  

## 5. Getting Started <a id="getting-started"></a>

**Quick Deploy with `@hazbase/factory`**

You can deploy any contract to a target chain by cloning this repo, opening the directory of the contract you want, and running the deploy command with a chain ID.

```bash
# 1) Clone the repository
git clone https://github.com/hazbase/contracts.git
cd contracts/<contranct directory>

# 2) Open the directory of the contract you want to deploy
#    (example: CircuitBreakerAMM)
cd contracts/CircuitBreakerAMM

# 3) Deploy to the specified chain ID
npx @hazbase/factory deploy --chainId <CHAIN_ID>
# e.g., --chainId 1 (Ethereum), 137 (Polygon), 8453 (Base), etc.
```

> Ensure your environment is configured according to `@hazbase/factory` requirements (RPC endpoint and deployer credentials). Use a testnet first to validate deployments.

## 6. Build, Test & Verify <a id="build-test-verify"></a>

Contracts are designed to be verifiable on Etherscan and compatible explorers. Configure your RPC and keys in your toolchain. For determinism, pin compiler versions and enable optimizer settings consistently. Provide deployment scripts and verification tasks to reproduce deployments.

## 7. ZK Circuits (circom/snarkjs) <a id="zk-circuits"></a>

This project may include Circom circuits and Groth16 verifiers. To ensure reproducibility and security, **do not commit** private inputs or witness files (`*.wtns`). Do not bundle large SRS files (`*.ptau`); instead document their trusted source and checksum in the README.

**Typical workflow (example)**
```bash
# Compile circuit
circom circuit.circom --r1cs --wasm

# Verify zkey against r1cs and SRS (ptau)
snarkjs zkey verify circuit.r1cs pot15_final.ptau circuit.zkey

# Export verification key and compare
snarkjs zkey export verificationkey circuit.zkey vk.json
diff -u vk.json verification_key.json
```

**Security notes**
- Never commit real inputs or witness files.  
- Prefer publicly audited SRS/PTAU and publish their hashes and source.  
- Document Phase 2 (zkey) provenance: participants, beacons, and SHA-256 of the final zkey.  

## 8. Security Model & Operational Guidance <a id="security-model-operational-guidance"></a>

- The code is provided "AS IS" without warranties; conduct independent audits before mainnet use.  
- Enable circuit-breaker and pause controls on production deployments; set conservative defaults.  
- Use multi-sig for privileged roles and timelock for upgrades.  
- Run allowlists/blacklists where required by compliance; segregate duties via distinct roles.  
- Back up governance/private keys securely; rotate keys and log all administrative actions.  

## 9. Contribution & Commit Signing <a id="contribution-commit-signing"></a>

We accept contributions under **Apache-2.0**. Use **DCO** (Developer Certificate of Origin) by adding a `Signed-off-by` line to commits. All commits should be cryptographically **signed** (SSH or GPG) so that they show as **Verified** on GitHub.

```bash
# Example (DCO + signed)
git commit -S -s -m "feat: add new module"
```

## 10. License <a id="license"></a>

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this project except in compliance with the License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 .

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the **LICENSE** file for the specific language governing permissions and limitations under the License.

## 11. Acknowledgements & Attribution <a id="acknowledgements-attribution"></a>

- OpenZeppelin Contracts (MIT)  
- circom and snarkjs (MIT)  
- Community contributors and auditors  

## 12. Disclaimer & Patents <a id="disclaimer-patents"></a>

This repository may interact with domains where regulatory and compliance obligations vary by jurisdiction. **Nothing herein constitutes legal, financial, or investment advice.** You are responsible for operating compliant deployments.

**Patents:** The project is licensed under Apache-2.0, which includes a patent license from contributors for their contributions as defined by the license. Your use of this code does not grant any additional patent rights beyond those provisions. For any proprietary cross-chain or asset-transfer claims held by the maintainers, separate licensing may be required for specific implementations outside the scope of this repository.
/**
 * hardhat.config.ts — Flare Coston2 Testnet deployment toolchain.
 *
 * Phase 6 / Prompt 101. Targets the Flare C-chain EVM (chain id 114) with the
 * CANCUN EVM version, per the master plan (Solidity 0.8.24 + Cancun rules) and
 * the official flare-hardhat-starter kit conventions.
 *
 * Research-backed decisions (dev.flare.network + Hardhat docs, 2026-08-09):
 *
 * * **Hardhat v2 (2.26.x)** — the battle-tested major that the Flare periphery
 *   tooling and @nomicfoundation/hardhat-toolbox target. (The v3 ESM-first
 *   major is rolling out; the config below stays v2-compatible so the whole
 *   plugin ecosystem works, and is a small migration later if we move.)
 * * **EVM version `cancun`** — Flare Coston2 supports every EVM opcode up to
 *   and including the Cancun hard fork; set via `solidity.settings.evmVersion`
 *   (valid in solc >= 0.8.20).
 * * **RPC** — the canonical public Coston2 endpoint
 *   `https://coston2-api.flare.network/ext/C/rpc` (same constant the enclave's
 *   config.py defaults to — one source of truth across phases).
 * * **Gas** — NO hardcoded gasPrice/gas. Coston2 is EVM-compatible and
 *   supports EIP-1559 (type-2) plus legacy (type-0); Hardhat/ethers auto-fetch
 *   dynamic fees from the RPC. Hardcoding caps here would fight the fee market.
 * * **Accounts** — the deployer key is loaded from the environment ONLY
 *   (`DEPLOYER_PRIVATE_KEY` via dotenv), never committed to source. When the
 *   key is absent (CI / fresh clone), `accounts` is `[]` and only
 *   read/compile tasks work — deployments fail loudly at the signing step
 *   (fail-closed, no fake key ever used).
 * * **Verification** — Coston2 runs a Blockscout explorer
 *   (coston2-explorer.flare.network) with an Etherscan-compatible API; the
 *   `etherscan.customChains` entry enables `hardhat verify` against it.
 */

import type { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";

// Load .env (blockchain/.env) if present; never requires it for compile tasks.
dotenv.config();

const DEPLOYER_PRIVATE_KEY: string = process.env.DEPLOYER_PRIVATE_KEY ?? "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      // Cancun is fully supported by Flare Coston2 and by solc >= 0.8.20.
      evmVersion: "cancun",
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      // Sensible default matching the compiler's evmVersion below. (Note: it does
      // NOT by itself make fork eth_calls work on chain 114 — Hardhat has no
      // hardfork-activation history for it, so deploy.ts runs its fork pre-flight
      // code-presence check only and defers live resolution to post-deploy.)
      hardfork: "cancun",
    },
    coston2: {
      url: "https://coston2-api.flare.network/ext/C/rpc",
      chainId: 114,
      // Empty accounts when the key is missing (compile/test-safe); the
      // deploy scripts assert the key is present before signing.
      accounts: DEPLOYER_PRIVATE_KEY ? [DEPLOYER_PRIVATE_KEY] : [],
    },
  },
  // NOTE: solidity-coverage options (skipFiles / viaIR) live in .solcover.js.
  // The `coverage:` block previously defined here was SILENTLY IGNORED by
  // solidity-coverage 0.8.17's hardhat plugin — it reads .solcover.js / the
  // --solcoverjs flag via loadSolcoverJS (verified in the plugin source,
  // 2026-08-10), not the hardhat `coverage:` key. See .solcover.js for the
  // effective config.
  etherscan: {
    apiKey: {
      coston2: process.env.FLARE_EXPLORER_API_KEY ?? "",
    },
    customChains: [
      {
        network: "coston2",
        chainId: 114,
        urls: {
          apiURL: "https://coston2-explorer.flare.network/api",
          browserURL: "https://coston2-explorer.flare.network",
        },
      },
    ],
  },
};

export default config;

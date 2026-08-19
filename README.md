# Flare Verifiable RAG

**Enterprise Knowledge Oracle — Cryptographically Verifiable AI on Flare Network**

An AI system where every answer is backed by a hardware-attested proof, live oracle data, and on-chain settlement. No hallucinations, no fabricated data, no "trust me."

**Live deployment:** [flare-verifiable-rag.vercel.app](https://flare-verifiable-rag.vercel.app)
**Smart contract:** [0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897](https://coston2-explorer.flare.network/address/0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897) (Flare Coston2, Chain 114)
**DoraHacks submission:** [dorahacks.io/buidl/47880](https://dorahacks.io/buidl/47880)

---

## The Problem

Traditional AI systems give you answers you can't verify. A language model generates text, and you have to *trust* that the underlying data was real, the computation was correct, and nobody tampered with the result. For enterprises in finance, healthcare, and law, that trust is unacceptable.

This system eliminates the trust requirement entirely. Every answer comes with a cryptographic proof that it was computed inside a hardware-isolated environment, using live data from Flare oracles, and verified on-chain before anyone sees it.

---

## How It Works — The Complete System

The architecture has four layers. Each layer enforces a specific guarantee, and together they form a chain of verified computation from your browser to the blockchain.

### Layer 1: Client (Next.js 14 + Web3)

```
Browser → AES-GCM-256 encryption → TLS 1.3 → Enclave
```

When you connect your wallet (MetaMask, RainbowKit) on Flare Coston2 and submit a document or query, two things happen:

1. **Client-side encryption** — Your payload is encrypted in the browser using AES-GCM-256 via the Web Crypto API. The encryption key is never sent to any server. Raw plaintext never touches disk or unencrypted storage.

2. **Blind proxy** — The encrypted ciphertext is sent directly to the TEE enclave endpoint. The Next.js server acts as a relay — it never decrypts, never caches, never logs the data.

**Key files:**
- `frontend/src/crypto/client_encryption.ts` — AES-GCM-256 encryption using Web Crypto API
- `frontend/src/components/SecureUploader.tsx` — Document upload with client-side encryption
- `frontend/src/components/ConnectWallet.tsx` — RainbowKit wallet connection
- `frontend/src/app/providers.tsx` — Wagmi + QueryClient + RainbowKit configured for Coston2

**Tech stack:** Next.js 14 (App Router), React 18, Wagmi v2.5.11, Viem v2.8.18, RainbowKit v2.0.2, Tailwind CSS, Framer Motion.

### Layer 2: TEE Enclave (Tokio Rust gRPC + Intel TDX / AMD SEV-SNP)

```
Encrypted payload → Decrypt in RAM → Process → Generate ZKP → Sign → Return proof
```

This is the core of the system. The enclave runs inside a Google Cloud Confidential Virtual Machine — either Intel TDX (c3-standard-4) or AMD SEV-SNP (n2d-standard-2). Hardware-level memory encryption means the host operating system, the hypervisor, and cloud administrators see only ciphertext. Nobody can inspect what the enclave is computing.

**The processing pipeline:**

1. **Attestation** — On boot, the enclave requests a vTPM OIDC token from the local Confidential Space server (`http://localhost/v1/token`). This token proves the enclave is running in a real Confidential VM with the exact container image that was compiled and audited.

2. **Decryption** — The encrypted payload is decrypted inside RAM. The container filesystem is read-only — nothing is ever written to disk.

3. **Deterministic symbolic graph engine** — Instead of probabilistic vector embeddings (which introduce drift and non-determinism), this system uses a Rust-based deterministic symbolic knowledge graph. Documents are parsed into Abstract Syntax Trees (ASTs), indexed into Directed Acyclic Graphs (DAGs), and queried using exact graph traversal with O(k) time complexity.

4. **Zero-knowledge proof** — The computation is verified by generating a halo2 ZKP over BN254 elliptic curves inside volatile memory. The proof attests that the output was derived deterministically from the document state under the query predicate, without external tampering.

5. **Memory scrubbing** — Immediately after proof generation, all decrypted data buffers are zeroed using Rust's `zeroize` crate. The enclave holds no persistent state.

**Key files:**
- `enclave/enclave_grpc/src/main_grpc.rs` — Tokio async entry point, graceful shutdown, Sentry integration
- `enclave/enclave_grpc/src/grpc_server.rs` — Tonic gRPC service (ExecuteQuery, GetAttestationToken, StreamFtsoFeeds)
- `enclave/enclave_grpc/src/tls_config.rs` — mTLS via rustls (server + client certificate validation)
- `enclave/enclave_grpc/src/middleware/rate_limit.rs` — Token bucket rate limiting (100 req/sec per client)
- `enclave/enclave_grpc/src/metrics.rs` — Prometheus `/metrics` endpoint
- `enclave/enclave_grpc/src/attestation/` — IETF RATS EAT builder, TDX/SEV-SNP hardware interfaces, attestation verifier
- `enclave/enclave_grpc/src/kms/` — GCP Cloud KMS MPC wallet (2-of-2 threshold ECDSA signing)
- `enclave/enclave_grpc/src/zktls/` — Sub-second zkTLS proxy (TLS 1.3 → X.509 chain verification → proof generation)
- `enclave/enclave_grpc/src/ftso_provider/` — Enclave-hosted FTSO v2 data provider node (multi-exchange WebSocket fetchers, volume-trimmed median, price submission)
- `enclave/src/rag_engine/` — Rust deterministic symbolic graph engine (AST parser, trie, DAG, ZKP circuits)
- `enclave/src/main.py` — Python FastAPI gateway (legacy, runs alongside the Rust core)

**Tech stack:** Rust 2021, Tokio 1.36, Tonic 0.10, prost 0.12, tower 0.4, rustls 0.21, halo2_proofs 0.3.5, Python 3.11, FastAPI, Uvicorn.

### Layer 3: Blockchain (Solidity 0.8.24 + Flare Coston2)

```
Proof + Attestation → Verify on-chain → Update state
```

The smart contracts are the final gatekeeper. Before any state changes, the contract verifies multiple conditions:

**VerifiableRAG.sol** (`0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897`):

1. **Container digest** — The submitted image hash must match `approvedImageDigest`. Any source code change alters the container hash, causing attestation to fail.

2. **TEE attestation** — The vTPM OIDC token proves the computation ran inside a real Confidential VM.

3. **ZKP verification** — The halo2 zero-knowledge proof over BN254 is verified on-chain.

4. **FTSO v2 staleness** — Price feeds must be fresh (Δt ≤ 300 seconds from `block.timestamp`).

5. **FDC data** — Web2 data must have valid Merkle proofs from the Flare Data Connector network.

**Contract interfaces:**
- `verifyAndSettleRAG(vtpmToken, zkpProof, queryHash, priceFeedValue) → bool`
- `verifyWeb2Data(fdcProof) → bool`
- `getRealtimePrice(feedId) → uint256`
- `executeKmsSignedAction(txBytes) → bool` (MPC wallet signed transactions)

**ZkTlsRelayer.sol** — Verifies sub-second zkTLS proofs from the enclave, bypassing the 90-second FDC voting round. Uses `ecrecover` to verify the enclave's secp256k1 signature against the registered identity.

**Key files:**
- `blockchain/contracts/VerifiableRAG.sol` — Core settlement contract
- `blockchain/contracts/ZkTlsRelayer.sol` — zkTLS proof relay
- `blockchain/contracts/interfaces/` — IFtsoV2, IFdcVerification, IWeb2Json, IKmsVerifiedWallet
- `blockchain/test/` — 120 Hardhat tests
- `blockchain/scripts/` — Deploy, FTSO v2 read, FDC attestation, zkTLS relay demo

**Tech stack:** Solidity 0.8.24 (Cancun EVM), Hardhat 2.29, OpenZeppelin 5.6.1, Flare Periphery Contracts 0.1.52.

### Layer 4: Infrastructure (Bazel + Terraform + Docker)

```
Source code → Hermetic Bazel build → Distroless Docker → GCP Confidential VM
```

**Hermetic builds with Bazel:**

Every component compiles in an isolated sandbox with explicitly declared inputs and outputs. This makes builds byte-for-byte reproducible on any machine.

| Domain | Rule set | Pinned version |
|---|---|---|
| Rust (enclave) | `rules_rust` + `crate_universe` | Rust 1.85.0 |
| Solidity (blockchain) | solc 0.8.24 (sha256-pinned binary) | Cancun EVM |
| TypeScript (frontend) | `aspect_rules_ts` | TypeScript via pnpm lock |
| Container images | `rules_oci` | Distroless static |

**Docker images:**
- Frontend: Next.js 14 standalone, 307 MB, 9 layers, non-root user
- Enclave: Static musl binary in distroless, 23.5 MB (under 25 MB bar)

**Terraform (GCP):**
- `infra/terraform/ConfidentialSpace.tf` — Provisioning Confidential VM (Intel TDX or AMD SEV-SNP)
- `infra/terraform/workload_identity.tf` — Workload Identity Pool + Provider + IAM bindings
- Attribute condition: `(swname=='CONFIDENTIAL_SPACE') AND (image_digest==approved_digest)`

**Key files:**
- `WORKSPACE.bazel`, `MODULE.bazel`, `BUILD.bazel` (root + per-workspace)
- `skaffold.yaml` — Local dev loop with minikube hot-reload
- `infra/terraform/` — GCP infrastructure as code
- `.github/workflows/build-tee.yml` — CI pipeline (SHA-pinned actions)
- `.github/workflows/bazel-ci.yml` — Hermetic build checks on PRs

---

## Flare Ecosystem Integration

### Flare Data Connector (FDC)

The FDC provides cryptographic proof that a specific HTTPS endpoint returned specific data at a specific time.

**Flow:**
1. You submit an attestation request to FdcHub with a URL, HTTP method, and jq selector.
2. Independent Flare verifier nodes fetch the URL, verify the TLS certificate chain, and evaluate the jq selector.
3. When M-of-N verifiers agree (~90 second voting round), the payload hash is compiled into a Merkle root on FdcHub.
4. `VerifiableRAG.sol` calls `IFdcVerification.verifyWeb2Json()` to validate the Merkle proof.

**Function selector:** `0x0aa05fe3` (verified in deployed bytecode on Coston2)
**FDC protocol ID:** 200 (governance-configured)
**Request fee:** 1000 wei (C2FLR)

### Flare Time Series Oracle (FTSO v2)

FTSO v2 delivers low-latency financial price feeds with single-block finality (~1.8 seconds).

**Feed IDs (bytes21, deterministic):**
```
FXRP/USD: 0x015852502f55534400000000000000000000000000
BTC/USD:  0x014254432f55534400000000000000000000000000
ETH/USD:  0x014554482f55534400000000000000000000000000
```

**Contract interface:** `IFtsoV2.getFeedById(bytes21) → (uint256 value, int8 decimals, uint256 timestamp)`
**Price formula:** `price_usd = value / 10^decimals`
**Staleness:** Δt ≤ 300 seconds from `block.timestamp`

### GCP KMS MPC Wallet (Multi-Party Computation)

The enclave operates as an autonomous Web3 wallet using 2-of-2 threshold ECDSA over secp256k1.

**Signing flow:**
1. Enclave generates IETF RATS EAT (CBOR/COSE-Sign1, RFC 9334).
2. Submits EAT to GCP Workload Identity Pool → STS issues IAM credentials.
3. IAM credentials → Cloud KMS `Decrypt` → releases enclave key shard (FIPS 140-2 Level 3 HSM-backed).
4. Enclave shard + operator shard → threshold ECDSA signature.
5. Signature sent via `eth_sendRawTransaction`.
6. Key shard zeroized immediately.

**On-chain verification:** `VerifiableRAG.sol` implements `IKmsVerifiedWallet.sol`, using `ecrecover` to verify the composed public key matches the registered enclave address.

### zkTLS Proxy (Sub-Second Web2 Attestation)

Bypasses the 90-second FDC voting round by generating proofs inside the TEE:

1. Opens a direct TLS 1.3 session with the target Web2 endpoint.
2. Captures the server's X.509 certificate chain during the handshake.
3. Verifies the chain against the embedded Mozilla Root CA bundle (webpki-roots).
4. Evaluates jq selectors using jaq-all (the same engine Flare's FDC attestor network uses).
5. Generates a signed proof with the enclave's secp256k1 key.
6. `ZkTlsRelayer.sol` verifies via `ecrecover` against the registered identity.

**Latency:** ~2.4 ms median (vs 500 ms budget).

---

## Enterprise Features

### Internationalization (i18n)

Five languages supported out of the box via next-intl:

| Locale | Language | Layout |
|---|---|---|
| `en` | English | LTR (default) |
| `es` | Spanish | LTR |
| `zh` | Mandarin Chinese | LTR |
| `ja` | Japanese | LTR |
| `ar` | Arabic | RTL |

Language selection persists in localStorage and is auto-detected via Accept-Language headers.

### Security Honeypot Framework

The middleware intercepts requests to known malicious paths (`/admin`, `/.env`, `/v1/debug`, `/wp-login.php`), logs attacker telemetry to Sentry, delays the response (wasting scanner time), and returns a generic 404 with no server information.

### AI Developer Copilot

A local, zero-network knowledge engine running in a Web Worker. It generates:

- **FDC Web2Json selectors** — Give it any HTTPS URL + jq selector + ABI type, and it builds the exact ABI-encoded request hex.
- **Solidity boilerplate** — Emits integration code matching this repo's exact interfaces.
- **FTSO v2 feed IDs** — Lists all available feeds with their deterministic bytes21 identifiers.
- **Architecture Q&A** — Explains how every component works, from TEE attestation to on-chain settlement.

No API keys, no network calls, no data leaves the browser.

### SRE & Error Tracking

- **Sentry** — Client + server error tracking via `@sentry/nextjs`
- **ErrorBoundary** — Catches React crashes, renders a "Report Bug" UI, logs to Sentry
- **DiagnosticsPanel** — Shows recent errors locally without exposing to end users
- **gRPC health protocol** — Standard `grpc.health.v1.Health` implementation
- **Prometheus /metrics** — Price submission counts, reconnect telemetry, live aggregated prices

---

## Repository Layout

```
flare-verifiable-rag/
├── blockchain/                     # Hardhat + Solidity 0.8.24 (Coston2)
│   ├── contracts/
│   │   ├── VerifiableRAG.sol       # Core settlement contract
│   │   ├── ZkTlsRelayer.sol        # zkTLS proof relay
│   │   └── interfaces/             # IFtsoV2, IFdcVerification, IKmsVerifiedWallet
│   ├── test/                       # 120 Hardhat tests
│   └── scripts/                    # Deploy, FTSO v2 read, FDC attestation
├── enclave/                        # TEE enclave
│   ├── enclave_grpc/               # Tokio Rust gRPC core
│   │   ├── src/
│   │   │   ├── main_grpc.rs        # Entry point, graceful shutdown, Sentry
│   │   │   ├── grpc_server.rs      # Tonic gRPC service
│   │   │   ├── tls_config.rs       # mTLS (rustls)
│   │   │   ├── metrics.rs          # Prometheus /metrics
│   │   │   ├── middleware/         # Rate limiting (tower::limit)
│   │   │   ├── attestation/        # IETF RATS EAT, TDX, SEV-SNP, verifier
│   │   │   ├── kms/                # GCP KMS MPC wallet
│   │   │   ├── zktls/              # zkTLS proxy + proof generator
│   │   │   └── ftso_provider/      # FTSO v2 data provider node
│   │   ├── proto/                  # Protobuf definitions
│   │   ├── tests/                  # 84 Rust tests
│   │   └── benches/               # zkTLS latency benchmarks
│   ├── src/                        # Python FastAPI gateway
│   └── tests/                      # 398 Python tests
├── frontend/                       # Next.js 14 Web3 client
│   └── src/
│       ├── app/                    # Routes: /, /upgrade, /profile, /settings
│       ├── components/             # 12 components (Header, AccountPopover, CopilotDrawer, etc.)
│       ├── lib/                    # copilot_engine, encryption, diagnostics, settings
│       ├── workers/                # Web Worker for copilot
│       └── tests/                  # 28 frontend tests
├── infra/terraform/                # GCP Confidential VM, WIF, KMS
├── scripts/                        # Directory scaffolding
├── messages/                       # i18n dictionaries (en, es, zh, ja, ar)
├── .github/
│   ├── workflows/                  # CI: build-tee.yml, bazel-ci.yml
│   └── scripts/                    # audit-no-mock.sh
├── WORKSPACE.bazel                 # Bazel root workspace
├── MODULE.bazel                    # Bzlmod dependencies
├── skaffold.yaml                   # Local dev loop
└── .teedigest                      # Container image SHA-256 digest
```

---

## Developer Commands

```bash
# Install dependencies
pnpm install

# Frontend
cd frontend && pnpm dev          # Development server (localhost:3000)
cd frontend && pnpm build        # Production build
cd frontend && npx jest          # Run 28 tests
cd frontend && npx next lint     # ESLint check

# Blockchain
cd blockchain && npx hardhat test            # Run 120 tests
cd blockchain && npx hardhat run scripts/read_ftso_v2.ts --network coston2    # Live prices
cd blockchain && npx hardhat run scripts/request_fdc_attestation.ts --network coston2  # Live FDC

# Enclave (Rust)
cd enclave/enclave_grpc && cargo test       # Run 84 tests
cd enclave/enclave_grpc && cargo run        # Start gRPC server

# Enclave (Python)
cd enclave && pytest tests/                 # Run 398 tests

# Bazel (hermetic builds)
bazel build //...               # Build everything hermetically
bazel test //...                # Test everything hermetically

# Audit
bash .github/scripts/audit-no-mock.sh       # Verify zero mock data
```

---

## Zero-Mock Policy

This repository enforces one non-negotiable rule: **everything is real, or it does not ship.**

- Zero hardcoded API keys or private keys
- Zero mock/stub/fake data in production code
- Zero hardcoded prices or fallback values
- Zero console.log/warn/error in production frontend code
- Zero TODO/FIXME in production code
- Zero placeholder text (lorem ipsum, dummy data)
- All data connections are live (FTSO v2, FDC, Coston2 RPC)
- All test doubles exist only in test directories

**Enforcement:** `.github/scripts/audit-no-mock.sh` runs five mechanical scans and exits non-zero on any violation. It runs in CI as a gate.

---

## Test Results

| Component | Tests | Status |
|---|---|---|
| Frontend (CopilotEngine + AccountPopover) | 28 | All passing |
| Rust Enclave (gRPC, attestation, KMS, zkTLS, FTSO, metrics) | 84 | All passing |
| Python Enclave (gateway, crypto, FDC, attestation) | 398 (offline) | All passing |
| Blockchain (VerifiableRAG, ZkTlsRelayer, KmsWallet, FDC, FTSO) | 120 | All passing |
| **Total** | **630** | **All passing** |

---

## Contract Addresses (Flare Coston2 Testnet)

| Contract | Address |
|---|---|
| VerifiableRAG.sol | `0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897` |
| FlareContractRegistry | `0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019` |
| FtsoV2 (registry-resolved) | `0xC4e9c78EA53db782E28f28Fdf80BaF59336B304d` |
| FdcHub (registry-resolved) | `0x48aC463d7975828989331F4De43341627b9c5f1D` |
| Deployer Wallet | `0xDA5a3D21D7EC1012965548E3443ae25c4b9D56A7` |

---

## Infrastructure

| Component | Provider | Free Tier |
|---|---|---|
| Blockchain | Flare Coston2 Testnet | Unlimited deployments, free testnet tokens |
| CI/CD | GitHub Actions | 2,000 build minutes/month |
| Container Registry | GHCR | 500 MB free storage |
| Frontend Hosting | Vercel | 100 GB/month bandwidth |
| Crash Tracking | Sentry | 5,000 events/month |
| Enclave VM | GCP Confidential Space | Free trial allocation |

---

## License

MIT

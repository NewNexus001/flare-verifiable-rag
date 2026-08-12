# flare-verifiable-rag

**A verifiable Retrieval-Augmented Generation (RAG) AI agent** built for the
Flare Summer Signal Hackathon — Track 2: **Confidential Compute**.

The short version: an AI assistant whose answers are only as trustworthy as the
data behind them. So instead of taking anything on faith, this system runs the
entire pipeline inside a **hardware-enforced confidential environment**
(Google Cloud Confidential Space), reads every price and every external fact
from **live Flare oracles** (FTSO v2, Flare Data Connector), and proves to the
chain — cryptographically — exactly which container image produced which
result. No guesswork, no fabricated data, no "trust me."

---

## Architecture at a glance

```
                    ┌──────────────────────────────────────────┐
                    │                frontend/                  │
                    │        Next.js 14 · Web3 UI (Wagmi)       │
                    │   encrypts payloads client-side (blind)   │
                    └───────────────────┬───────────────────────┘
                                        │  TLS (encrypted payload)
                                        ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │                 enclave/  · Google Confidential Space (TEE)      │
   │                                                                  │
   │   FastAPI service · processing in RAM only · vTPM attestation    │
   │   ├── crypto/        attestation fetch + transaction signing     │
   │   ├── rag_engine/    deterministic reasoning core (Rust)         │
   │   └── flare_client/  FTSO v2 + FDC live data ingestion           │
   │                                                                  │
   │   Identity = Workload Identity Federation, bound to the exact    │
   │   SHA-256 digest of this container (see .github/workflows)       │
   └───────────┬──────────────────────────────┬───────────────────────┘
               │                              │
               ▼                              ▼
   ┌────────────────────────┐   ┌───────────────────────────────────┐
   │        blockchain/      │   │   Flare Coston2 · chain 114       │
   │  Solidity 0.8.24        │◄──┤   FTSO v2 live prices             │
   │  validates TEE proofs   │   │   FDC-attested web2 data (Merkle) │
   │  before state changes   │   │   FlareContractRegistry (runtime) │
   └────────────────────────┘   └───────────────────────────────────┘
```

Three trust layers, working together:

1. **Trust the computation** — the enclave runs in a Confidential VM with a
   hardware-rooted vTPM. The exact container digest is recorded at build time
   and bound to the identity via Workload Identity Federation, so the chain
   knows precisely which code produced a result.
2. **Trust the data** — every value comes from live Flare infrastructure:
   FTSO v2 price feeds for markets, and FDC-attested data whose Merkle proofs
   are verified on-chain. Nothing is hardcoded, cached from a past run, or
   invented.
3. **Trust the state** — Solidity contracts gate every state change on a
   valid TEE attestation proof before they accept anything.

---

## Repository layout

```
flare-verifiable-rag/
├── .github/
│   ├── workflows/build-tee.yml     # TEE digest lock-in (SHA-pinned actions)
│   ├── dependabot.yml              # weekly grouped action updates
│   └── scripts/audit-no-mock.sh    # zero-mock enforcement gate (CI)
├── scripts/
│   ├── create_dirs.sh              # idempotent directory scaffold (bash)
│   └── create_dirs.ps1             # idempotent directory scaffold (PowerShell)
├── blockchain/                     # Hardhat + Solidity 0.8.24, targets Coston2
│   ├── contracts/interfaces/       # IFtsoV2, IFlareDataConnector, registry
│   └── scripts/                    # deployment pipeline
├── enclave/                        # Python/FastAPI confidential container
│   └── src/
│       ├── crypto/                 # vTPM attestation, signing
│       ├── rag_engine/             # deterministic reasoning core
│       └── flare_client/           # FTSO v2 + FDC live connectors
├── frontend/                       # Next.js 14 Web3 client
│   └── src/
│       ├── app/                    # routes, layout, error surfaces
│       └── components/             # wallet, encrypted uploader, boundaries
├── infra/terraform/                # GCP Confidential VM, WIF, KMS
├── package.json                    # root scripts, pnpm pinned to 10.4.1
├── pnpm-workspace.yaml             # workspace map: frontend + blockchain
├── turbo.json                      # task pipeline + caching rules
├── pnpm-lock.yaml                  # frozen, registry-verified dependency graph
├── .gitignore                      # artifacts, secrets, tfstate, digests
├── REAL-DATA-SOURCES.md            # web-verified live data sources (read this)
└── README.md                       # you are here
```

Only `frontend/` and `blockchain/` are pnpm workspaces — they are Node
projects. `enclave/` (Python) and `infra/` (Terraform) are deliberately
**not** part of the Node dependency graph; turbo.json declares their tasks
with `cache: false` so TEE build artifacts and Terraform state are never
cached.

> The layout above is the **target architecture**. `enclave/` and `infra/`
> are scaffolded today and their contents land in later phases of the build
> plan; `blockchain/` and `frontend/` currently hold their workspace
> manifests. Nothing in this tree is fake — empty means *not built yet*,
> not *stubbed with made-up data*.

---

## Developer prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Node.js | `>=20.0.0` | Enforced by `engines`; developed on v26 |
| pnpm | `10.4.1` | Pinned via `packageManager`; install with `corepack enable` or `npm i -g pnpm@10.4.1` |
| Docker | any recent | Needed for `pnpm enclave:build` (Phase 4+) |
| Terraform | any recent | Needed for `pnpm infra:*` (Phase 2+) |
| gcloud + GCP project | — | Needed to deploy the Confidential VM and WIF |

> **Why so pinned?** Determinism is the point. A lockfile, a pinned package
> manager, SHA-pinned CI actions, and a frozen lockfile install mean the
> container digest CI records today is reproducible on any machine.

---

## pnpm commands

```bash
pnpm install                    # workspace install (CI uses --frozen-lockfile)
pnpm build                      # turbo run build  (frontend + blockchain)
pnpm lint                       # turbo run lint
pnpm dev                        # turbo run dev
pnpm enclave:build              # build the enclave image (never cached)
pnpm infra:init                 # terraform init
pnpm infra:plan                 # terraform plan
pnpm infra:apply                # terraform apply
```

**A note on the non-Node tasks.** `enclave:build` and `infra:init|plan|apply`
are declared in `turbo.json` as declarative pipelines with `cache: false` —
they are invoked through the root scripts above, not `turbo run`, because no
package owns them. Build outputs exclude `.next/cache/**`, and the global env
list already includes the Sentry variables so telemetry config changes
correctly invalidate caches.

---

## Zero-mock policy

This repository has one non-negotiable rule:

> **Everything is real, or it does not ship.**

Concretely, the codebase will never contain:

- hardcoded JSON fixtures or fabricated prices — all market data is read live
  from FTSO v2 on Coston2;
- simulated API responses — all external facts are FDC-attested and verified
  on-chain;
- hardcoded on-chain addresses in logic — contracts resolve addresses at
  runtime through the `FlareContractRegistry`;
- private keys or secrets committed anywhere — keys come from environment or
  secret-manager references, never literals;
- unverified RPC endpoints — the only endpoints allowed are the canonical
  ones documented in `REAL-DATA-SOURCES.md`.

**Enforcement.** `.github/scripts/audit-no-mock.sh` runs five mechanical scans
(mock markers, private-key material, hardcoded address lists, RPC endpoints
outside the allowlist, and hardcoded addresses) and exits non-zero on any
violation. It runs in CI as a gate (`build-tee.yml`), so a merge that sneaks
in fabricated data fails the build loudly. The web-verified source manifest
lives in `REAL-DATA-SOURCES.md` — when in doubt, read that file.

---

## CI & supply chain

- **`build-tee.yml`** — every push to `main` builds the enclave image with
  `--no-cache`, records its exact SHA-256 digest to `.teedigest`, and uploads
  it. That digest is the input to the Workload Identity Pool condition: only a
  container with that digest can assume the TEE identity. All six actions are
  pinned by commit SHA, and Dependabot proposes verified bumps weekly as one
  grouped pull request.
- **Deterministic installs** — CI runs `pnpm install --frozen-lockfile`, which
  fails hard if the lockfile and the manifest disagree.

---

## Status

Phase 1 (monorepo scaffold & workspace mapping) is complete — verified in
prompts 001–020, including the zero-mock audit gate. Phase 2 (infrastructure
as code & GCP Confidential VM) is in progress: the Terraform module under
`infra/terraform/` currently configures the provider, input variables, and the
Confidential Space workload VM (AMD SEV-SNP on N2D). The build plan runs
across ten phases, from infrastructure and the reasoning core through
contracts, attestation, data connectors, the frontend, and a final
SRE/audit/deploy pass. Each phase lands verified: every file is parsed,
linted, executed, and reviewed before the next one starts.

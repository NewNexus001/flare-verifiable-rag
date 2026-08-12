# PROJECT-STATE.md — Where We Stopped (Flare Hackathon)

> Recovered from the archived Freebuff chat (`3D Objects/freebuff crosschecker`,
> chat `2026-07-31T13-27-10.901Z`, 203 messages, 85MB). Written Aug 10, 2026.

## 🎯 The Mission

**`flare-verifiable-rag`** — a confidential RAG system for the **Flare hackathon**:
an enclave (Confidential Space / vTPM-attested) that answers queries in RAM, produces
ZKP proofs, and settles answers on-chain via **Flare Coston2** (`VerifiableRAG.sol`)
using FDC (FTSO price feeds + FDC attestations). Built prompt-by-prompt from a
200-prompt blueprint (Phases 1–6).

## 📍 Where We Stopped

**Prompt 126 COMPLETE. Phase 7 (121–140 — FDC Web2Json verification engine) IN PROGRESS.** Phase 6 (101–120) FULLY DONE.

- ✅ **126 (`encode_web2json_request(url, json_path)` convenience form): PASSED with LIVE proof** —
  added the prompt's exact signature as a typed `@overload` on the existing encoder function:
  `encode_web2json_request(url: str, json_path: str) -> bytes` now builds a request from just a URL + jq
  path. **HONEST FLAG (prompt-vs-protocol):** the FDC Web2Json protocol has NO `json_path` field — the real
  field is `postProcessJq` (a jq filter, e.g. `.name`) plus `abiSignature`; the convenience form maps
  `json_path → postProcessJq` and defaults `abi_signature="string"` (the reference `.name → string`
  extraction, live-verified VALID by the official verifier). Proof: convenience form output == FRESH official
  verifier response byte-for-byte (800 bytes, MIC zeroed, True) + == captured reference vector; round-trip
  decode True. Fail-closed guards: missing/blank json_path, dataclass form with stray json_path or
  request-field kwargs (reviewer finding — silently-ignored kwargs now raise TypeError). Encoder tests
  **38 passed** (incl. 2 live), full enclave suite **486 passed, 1 skipped**, audit exit 0, reviewer: no blockers.

- ✅ **125 (Python FDC request formatter `enclave/src/flare_client/fdc_encoder.py`): PASSED with LIVE proof** —
  NEW module encoding Web2Json attestation requests into the exact `abiEncodedRequest` bytes for
  `FdcHub.requestAttestation(bytes)`. **Byte-for-byte verified against Flare's OFFICIAL testnet verifier**
  (`https://fdc-verifiers-testnet.flare.network/verifier/web2/Web2Json/prepareRequest` — the same endpoint the
  official flare-hardhat-starter uses): our encoder output == verifier `abiEncodedRequest` (832/800 bytes,
  MIC region zeroed — verifier computes a response commitment, we default to the documented zero
  "no expected-response commitment" value). Layout proven: `pad32(attestationType "Web2Json") ||
  pad32(sourceId "PublicWeb2") || MIC(32B) || abi.encode(RequestBody 7-string struct)`. **CRITICAL catch
  (never-guess rule):** type/source are UTF-8 zero-padded strings — NOT keccak hashes, and NOT lowercase
  `web2json` (camelCase `Web2Json` is the exact string, from flare-hardhat-starter Web2Json.ts).
  Live chain: `FdcRequestFeeConfigurations.TypeAndSourceFeeSet` events prove `Web2Json/PublicWeb2 fee=1000 wei`
  is governance-configured, and `getRequestFee(our bytes)` returns **1000 wei** live. Validation mirrors the
  official web2-json request rules (HTTPS url, method whitelist, JSON-object headers/queryParams/body, length
  bounds). New tests: 29 passed (incl. 2 live: fresh verifier byte-identity + live fee), full enclave suite
  **477 passed, 1 skipped**, audit exit 0. Reviewer: no blockers (removed 2 dead imports).
  Followup: verifier/DA-layer pipeline + FdcHub submission is the next natural step (Prompts 126+).

- ✅ **124 (verifyWeb2Data queries IFdcVerification from ContractRegistry): PASSED with LIVE proof** —
  the function already resolves `IFdcVerification` via `contractRegistry.getContractAddressByName("FdcVerification")`
  (fail-closed `UnregisteredContract` on zero) and forwards the decoded `IWeb2Json.Proof` to
  `verifyWeb2Json`. Verified against the REAL Coston2 chain this prompt:
  (1) LIVE registry call `getContractAddressByName("FdcVerification")` → `0x906507E0B64bcD494Db73bd0459d1C667e14B933`
  (the real FdcVerificationProxy — name string correct); (2) EIP-1967 impl slot → `0x6e33205293ae1c6dcc91249951a5a67c863918a7`
  (ContractName: FdcVerification, v0.8.20); (3) canonical selector rebuilt from authoritative ABI components
  `verifyWeb2Json((bytes32[],(bytes32,bytes32,uint64,uint64,(string,string,string,string,string,string,string),(bytes))))`
  → `0x0aa05fe3`, and the DEPLOYED BYTECODE contains `0x0aa05fe3` (FOUND) while the old record `0xc35efe86`,
  flattened `0x90bfe3c1`, and prompt-bytes `0x63ab4402` are ALL ABSENT → **CORRECTED the wrong selector record**
  (never-guess rule); (4) LIVE `fdcProtocolId()` → **200** (researcher's "1 or 130" was WRONG; docs confirm 200),
  `relay()` → `0xa10B672D1c62e5457b17af63d4302add6A99d7dE`; (5) all 6 source URLs from the user's research were
  READ in full (flare-contracts-registry guide, fdc/overview, IFdcVerification reference, flare-ai-skills SKILL.md,
  foundry cross-chain-fdc, fdc-by-hand). Compile clean, 59 tests passing, audit exit 0, reviewer: no blockers.

- ✅ **123 (verifyWeb2Data in VerifiableRAG.sol): PASSED with honest deviation** — added
  `verifyWeb2Data(bytes calldata _fdcProof) public view returns (bool)` (the prompt's exact signature)
  that ABI-decodes to the real `IWeb2Json.Proof` struct and forwards to the LIVE registry-resolved
  `IFdcVerification.verifyWeb2Json` (the real Coston2 verifier — never a mock).
  New imports (IFdcVerification, IWeb2Json), +4 unit tests (59 passing total): true path, false path,
  UnregisteredContract fail-closed, undecodable-bytes revert. New `contracts/test/TestFdcVerification.sol`
  helper (branch-light, excluded from coverage). Compile clean, audit exit 0, reviewer: no blockers.
  **CORRECTION (Prompt 124, never-guess rule):** the selector recorded here/at 122 as `0xc35efe86` was
  WRONG (computed from a hand-typed placeholder `(bytes32[],tuple)` string, NOT the canonical expansion).
  Authoritative ABI `components` of the live FdcVerification impl `0x6e33205293ae1c6dcc91249951a5a67c863918a7`
  rebuild the canonical signature `verifyWeb2Json((bytes32[],(bytes32,bytes32,uint64,uint64,(string,string,string,string,string,string,string),(bytes))))`
  → selector `0x0aa05fe3`, and the DEPLOYED BYTECODE contains `0x0aa05fe3` (FOUND) while `0xc35efe86`,
  `0x90bfe3c1` (flattened), and `0x63ab4402` (prompt bytes variant) are all ABSENT. Corrected value: `0x0aa05fe3`.

- ✅ **122 (IFdcVerification.sol): PASSED with honest flag** — interface already on disk from Phase 6
  (`blockchain/contracts/interfaces/IFdcVerification.sol` — real Flare interface, inherits IWeb2JsonVerification + 8 others,
  plus `fdcProtocolId()`/`relay()`). **FLAGGED MISMATCH:** the prompt's literal signature `verifyWeb2Json(bytes)` is WRONG for the real
  protocol — official docs + LIVE Coston2 chain both declare `verifyWeb2Json(IWeb2Json.Proof calldata) external view returns (bool)`.
  LIVE proof: FdcVerificationProxy `0x906507E0B64bcD494Db73bd0459d1C667e14B933` → EIP-1967 impl `0x6e33205293ae1c6dcc91249951a5a67c863918a7` (FdcVerification),
  real struct selector `0x0aa05fe3` (canonical, verified in bytecode at Prompt 124) vs prompt's bytes selector `0x63ab4402` — MATCH? False. Kept the REAL struct signature (no mock, no lies),
  documented in FLARE-KNOWLEDGE.md. Compile artifacts fresh (Aug 10 12:03), audit exit 0.

- ✅ **121 (IFdcHub.sol with `requestAttestation(bytes) external payable`): PASSED** — interface already on disk from Phase 6
  (`blockchain/contracts/interfaces/IFdcHub.sol`), verified **against the LIVE Coston2 FdcHub** (`0x48aC463d7975828989331F4De43341627b9c5f1D`,
  verified source fetched from coston2-explorer API): deployed contract declares exactly
  `function requestAttestation(bytes calldata _data) external payable mustBalance`. Our interface matches 1:1
  (events `AttestationRequest`/`RequestsOffsetSet`/`InflationRewardsOffered` + view fns `requestsOffsetSeconds`/`fdcInflationConfigurations`/`fdcRequestFeeConfigurations`).
  Compile artifact fresh (Aug 10 12:03), ABI shows `requestAttestation(bytes)` payable, `npx hardhat test test/VerifiableRAG.test.ts` → **55 passing**, audit-no-mock exit 0.

- ✅ **118 (coverage >90% branch): PASSED at 90.68%** — journey: 47% → 83% → 88% → 89.8% → **90.68%**
- ✅ **REAL live deployment on Coston2**: `VerifiableRAG.sol` at
  **`0x02de55Dea3AAA45Bceefc69FfDF7db6a30F4fa46`**
  (tx `0x4a95abac21a1102820ff62c96cc2239167327d668797ce3d09d9c3ec25c086ba`)
- ✅ **Fork-based settle tests: 7/7 passing** against the live chain
- ✅ 4 code-reviewer fixes applied (config comment, padded test guard, `coverage`/`coverage:full` split, skipFiles globs)
- ✅ **Followup A done with live proof** — `.tools/119_livecheck.py` written & run:
  - chain_id 114 ✓, code bytes 6848 match artifact ✓
  - owner = `0x8079df375D00a1Aec65c2E9f1bd94b5Cd0d233De` (deployer key) ✓
  - contractRegistry = `0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019` (canonical Flare) ✓
  - approvedImageDigest = `25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421` ✓
  - priceFeedId = zero (unset — fail-closed) ✓
- ✅ **119 (zero hardcoded keys/mock feeds): PASSED** — static scan clean (no `0x`+64-hex keys, no mock prices, no hardcoded addresses in logic) + live on-chain check PASS (chain 114, code bytes 6848, owner, registry, digest all verified)
- ✅ **120 (audit-no-mock.sh Phase 6 PoW): PASSED** — exit code 0, all 5 checks OK (see below)

## ⏭️ What's Next (Phase 7+ of the blueprint)

1. **Phase 7 — Prompts 121–140: FDC Web2Json Verification Engine** (research base ready in `FLARE-KNOWLEDGE.md`)
2. Then Phase 8 (141–160 FTSO v2), Phase 9 (161–180 Next.js UI), Phase 10 (181–200 SRE + audit)

## ✅ Completed Phases (from the history)

| Phase | Prompts | Status |
|---|---|---|
| 1 — Monorepo scaffold | 001–020 | ✅ COMPLETE (git init, pnpm workspace, turbo, workflows, audit-no-mock.sh) |
| 2 — GCP Confidential VM IaC | 021–040 | ✅ COMPLETE (terraform: main.tf, variables.tf, ConfidentialSpace.tf — secure_boot/vtpm/integrity_monitoring) |
| 3 — Rust ZKP crate `indexer_rs` | 041–060 | ✅ COMPLETE (src/{lib,ast,trie,graph,zkp,ffi}.rs, tests, benches, maturin wheel, 120–123 tests, clippy/fmt/rustdoc clean) |
| 4 — Enclave Python service | 061–080 | ✅ COMPLETE (requirements.txt w/ CVE bumps, Dockerfile distroless non-root, main.py, processor.py, connector.py, crypto/, config.py, /health + /v1/query, pytest, docker build, audit) |
| 5 — Attestation engine + GCP vTPM/WIP | 081–100 | ✅ COMPLETE (attestation.py, jwt_parser.py, cli_attest.py, mock_vtpm.py tests, /v1/attestation, /health, audit-no-mock Phase 5 PoW, image digest extraction) |
| 6 — Solidity + Coston2 | 101–120 | ✅ **COMPLETE (119 verified clean + live, 120 audit PASS exit 0)** |

## 🔑 Key Facts & Addresses

- **Deployer key address**: `0x8079df375D00a1Aec65c2E9f1bd94b5Cd0d233De` (key saved in `blockchain/.env`)
- **Live contract**: `0x02de55Dea3AAA45Bceefc69FfDF7db6a30F4fa46` on Coston2
- **ContractRegistry (Coston2)**: `0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019`
- **RPC**: `https://coston2-api.flare.network/ext/C/rpc`, Chain ID 114, EVM `cancun`
- **Coverage scripts**: `coverage` = unit-only (`--testfiles 'test/VerifiableRAG.test.ts'`), `coverage:full` = everything
- **skipFiles**: `["interfaces", "test"]` (plain folder names — the plugin's glob `**` doesn't match on Windows)

## 📌 User Standing Rules

**See `RULES.md`** — the short version: 🚫 no mock data (ever, real live everything),
📚 research first (ask if empty, **and ask immediately when researcher-web fails — no excuse, no exception**),
🔁 always do my followups, 🧾 real proof from terminal, 🏗️ build like Google, 🤝 no lies,
⚡ full permissions stop asking, 🐢 slow & steady, 🔑 save secrets myself, 🔢 never skip numbers,
🙅 never guess/predict, ⚡ never hesitate — **stress the user** (ask, don't stall).

## 💾 Backup Notes (CRITICAL)

- The full chat history lives in `C:\Users\hp\3D Objects\freebuff crosschecker\` — **do not delete**
- The app's live data lives at `C:\Users\hp\.config\manicode\projects\flare-verifiable-rag\chats\`
  (that folder now has a fresh chat — the backup is the only copy of the real history)
- The last crash cause: `contextTokenCount = 248897` — session died of context bloat.
  **Keep conversations lean; use this file + RULES.md instead of re-pasting history.**

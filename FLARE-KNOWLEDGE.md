# FLARE-KNOWLEDGE.md — Flare Network Deep Knowledge Base

> Compiled Aug 10, 2026 from authoritative sources: dev.flare.network (official docs),
> flare-smart-contracts-v2 GitHub, flare-periphery-contracts. Zero guessing — every fact
> verified against official docs or the live Coston2 chain.

---

## 1. Networks & Configuration (official)

| Network | Chain ID | Native | HTTPS RPC | Explorer |
|---|---|---|---|---|
| **Flare Mainnet** | `14` | FLR (18 dec) | `https://flare-api.flare.network/ext/C/rpc` | flare-explorer.flare.network |
| **Coston2 (testnet)** | `114` | C2FLR (18 dec) | `https://coston2-api.flare.network/ext/C/rpc` | coston2-explorer.flare.network |
| **Songbird (canary)** | `19` | SGB (18 dec) | `https://songbird-api.flare.network/ext/C/rpc` | songbird-explorer.flare.network |
| **Coston (testnet)** | `16` | CFLR (18 dec) | `https://coston-api.flare.network/ext/C/rpc` | coston-explorer.flare.network |

- **Faucets:** Coston2 → `https://faucet.flare.network/coston2` (C2FLR, FXRP, USDT0). Coston → `/coston`.
- **Consensus:** Snowman++ (Avalanche lineage), PoS, delegation in-protocol, **block time ≈1.8s**, **single-slot finality**.
- **EVM:** fully EVM-compatible, supports all opcodes up to **Cancun**. EIP-2718 + EIP-1559 (Type 0/2), fees burned.
- **Address space:** 20-byte ECDSA, Ethereum-style.
- **FDC Verifier APIs:** `https://fdc-verifiers-testnet.flare.network/verifier/web2/api-doc` (Web2Json) etc. Public API key `00000000-0000-0000-0000-000000000000`.

## 2. FlareContractRegistry — THE source of truth

- **Same address on ALL four networks:** `0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019`
  (✅ matches what our VerifiableRAG.sol live state check returned — our code is correct)
- **Never hardcode protocol addresses** — always resolve dynamically via the registry.
  Official guide (dev.flare.network/network/guides/flare-contracts-registry): *"To ensure reliability, these
  contract addresses should always be retrieved dynamically via the Flare Contract Registry rather than
  hardcoding them... The registry is deployed at the same address across all Flare networks:
  0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019."*
- Methods: `getContractAddressByName(string)` (the method our VerifiableRAG.sol uses — matches official docs),
  `getContractAddressByHash(bytes32)`, `getAllContracts()`.
- Solidity shortcut library: `ContractRegistry.getFtsoV2()`, `getFdcVerification()`, `getFdcHub()`, `getRandomNumberV2()` etc. from `@flarenetwork/flare-periphery-contracts/coston2/ContractRegistry.sol`.
- **Registry name for FDC verification = `"FdcVerification"` (case-sensitive)** — confirmed two ways:
  (1) the live Coston2 registry call `getContractAddressByName("FdcVerification")` returns
  `0x906507E0B64bcD494Db73bd0459d1C667e14B933` (the real FdcVerificationProxy), and
  (2) the official flare-ai-skills FDC skill + flare-periphery examples use `ContractRegistry.getFdcVerification()`
  which wraps exactly that string lookup.

## 3. FTSOv2 (Flare Time Series Oracle v2)

- **Enshrined oracle** — inherits full economic security of the network. Block-latency feeds update **every ~1.8s block**.
- ~100 independent data providers selected via **stake-weighted VRF** each block; expected sample size 1.
- **Incremental delta updates:** base increment `1/2^13 ≈ 0.0122%`, deltas ∈ {−1, 0, +1}. Anchored to Scaling feeds (full commit-reveal, 90s epochs).
- **Volatility incentives** can temporarily raise sample size for a fee. Up to **1000 feeds** (crypto, equities, commodities), 2 weeks history.
- **Feed IDs are `bytes21`:** `0x01` (category) + 20-byte pair hex.
  - FLR/USD = `0x01464c522f55534400000000000000000000000000`
  - BTC/USD = `0x014254432f55534400000000000000000000000000`
  - ETH/USD = `0x014554482f55534400000000000000000000000000`
- **FtsoV2Interface (LTS)** key functions:
  - `getFeedById(bytes21) → (uint256 value, int8 decimals, uint64 timestamp)` (payable, fee may apply)
  - `getFeedByIdInWei(bytes21) → (uint256 valueWei, uint64 timestamp)`
  - `getFeedsById(bytes21[])`, `getFeedsByIdInWei(bytes21[])`
  - `getSupportedFeedIds()`, `getFeedIdChanges()`, `calculateFeeById(s)`, `getFtsoProtocolId()`
  - `verifyFeedData(FeedDataWithProof) → bool` (Merkle-verify anchor/Scaling feed data)
- Consume via `ContractRegistry.getFtsoV2()` (or `getTestFtsoV2()` in tests). **Staleness = our `REALTIME_MAX_AGE` (300s, symmetric Prompt 145) require.**

## 4. FDC (Flare Data Connector)

- **Enshrined oracle for external data.** 50%+ signature weight from data providers = consensus.
- Merkle tree — only the **root stored onchain** (Relay contract); responses + proofs served offchain via **DA Layer** (trustless — recompute root).
- **7 attestation types:** AddressValidity, EVMTransaction, Web2Json, Payment, ConfirmedBlockHeightExists, BalanceDecreasingTransaction, ReferencedPaymentNonexistence (last 3 mainly FAssets). Also XRPPayment/XRPPaymentNonexistence variants.
- **Workflow:** 1) `FdcHub.requestAttestation(...)` + fee → 2) providers batch by emission timestamp → 3) fetch+verify → 4) 50%+ signed Merkle root → Relay → 5) fetch proof from DA Layer → 6) contract verifies via `IFdcVerification.verify*`.
- **Fees:** minimum per type/source (`FdcRequestFeeConfigurations`); confirmed-request fee → providers; unconfirmed → burnt. Higher fee = better confirmation odds.
- **IFdcVerification** functions: `verifyAddressValidity`, `verifyBalanceDecreasingTransaction`, `verifyConfirmedBlockHeightExists`, `verifyEVMTransaction`, `verifyPayment`, `verifyReferencedPaymentNonexistence`, `verifyWeb2Json` (each takes its `I*.Proof` struct → bool), plus `fdcProtocolId()` and `relay()`.
- **`verifyWeb2Json` canonical selector (LIVE-VERIFIED):** `0x0aa05fe3` — rebuilt from the authoritative ABI
  `components` of the deployed FdcVerification impl `0x6e33205293ae1c6dcc91249951a5a67c863918a7` on Coston2,
  and CONFIRMED PRESENT in the deployed runtime bytecode (Prompt 124). Earlier records of `0xc35efe86` were
  WRONG (hand-typed placeholder tuple) and have been corrected. The prompt-text variant `verifyWeb2Json(bytes)`
  → `0x63ab4402` does NOT exist on chain.
- **`fdcProtocolId()` on Coston2 = 200 (LIVE call, Prompt 124)** — the researcher's "1 or 130" guess was WRONG;
  the live read returned 200, matching the flare-ai-skills skill (`isFinalized(200, roundId)` — "200 = FDC protocol ID")
  and the Foundry cross-chain guide ("protocol ID e.g. 200 for Coston2"). Always read it at runtime per the docs.
- **`relay()` on Coston2 = `0xa10B672D1c62e5457b17af63d4302add6A99d7dE` (LIVE call, Prompt 124).**
- **Proof age limits:** most chain types ≤14 days; AddressValidity & Web2Json no practical limit.
- **`attestationType`/`sourceId` are UTF-8 zero-padded bytes32 — NOT keccak hashes** (Prompt 125, verified two ways:
  the official verifier's `abiEncodedRequest` AND the decoded `TypeAndSourceFeeSet` event topics). For Web2Json on
  Coston2: `attestationType = "Web2Json"` (CAMELCASE — lowercase `web2json` reverts!), `sourceId = "PublicWeb2"`.
  Encoding layout (byte-identical to the official verifier, Prompt 125):
  `pad32(attestationType) || pad32(sourceId) || messageIntegrityCode(32B, zero = no expected-response commitment) ||
  abi.encode(RequestBody)` where RequestBody = the 7-string struct (url, httpMethod, headers, queryParams, body,
  postProcessJq, abiSignature). Our `enclave/src/flare_client/fdc_encoder.py` reproduces the official verifier bytes
  EXACTLY (verified 2026-08-11, 800-byte reference).
- **FDC request fee (LIVE, Prompt 125):** `FdcRequestFeeConfigurations.getRequestFee(abiEncodedRequest)` on Coston2
  returns **1000 wei** for `Web2Json`/`PublicWeb2` (governance `TypeAndSourceFeeSet` events list it; other combos
  e.g. EVMTransaction/testFLR ALSO exist at 1000 wei; `Web2Json`/`testIgnite` = 1.0 C2FLR). Fee contract reads only
  `_data[:32]` + `_data[32:64]` (type+source) and reverts "Type and source combination not supported" if unset.
- **Prompt 126 — convenience API note:** our `encode_web2json_request(url, json_path)` maps `json_path` →
  the protocol's `postProcessJq` field (jq filter) — Web2Json has NO `json_path` field. Default
  `abi_signature="string"` for the convenience form (reference `.name → string`, live VALID); numeric/bool
  extractions must pass `abi_signature="uint256"`/`"bool"` etc. Convenience form output is byte-identical
  to the official verifier (re-verified fresh, Prompt 126).
- **Official endpoints (flare-hardhat-starter .env.example, Prompt 125):** verifier
  `https://fdc-verifiers-testnet.flare.network` (POST `/verifier/web2/Web2Json/prepareRequest` with `X-API-KEY`;
  public test key `00000000-0000-0000-0000-000000000000`; returns `abiEncodedRequest`), DA Layer
  `https://ctn2-data-availability.flare.network` (POST `/api/v1/fdc/proof-by-request-round-raw`).
- **Official reference flow (flare-hardhat-starter scripts/fdcExample/Web2Json.ts):** verifier prepare →
  `FdcHub.requestAttestation(abiEncodedRequest, {value: getRequestFee(...)})` → roundId from receipt block timestamp
  (`floor((blockTs - firstVotingRoundStartTs)/votingEpochDurationSeconds)`, 1658430000 / 90s) → poll
  `Relay.isFinalized(200, roundId)` → DA Layer proof → `IFdcVerification.verifyWeb2Json(proof)`.
- **Proof age limits:** most chain types ≤14 days; AddressValidity & Web2Json no practical limit.

### Web2Json attestation (Phase 7 — our next big one)

- Request body (Solidity struct): `url` (absolute **HTTPS**, host whitelisted on mainnet — FIP.14 governance; testnet uses `PublicWeb2` source, no whitelist), `httpMethod` (GET/POST/PUT/PATCH/DELETE), `headers`, `queryParams`, `body` (stringified JSON), `postProcessJq` (restricted jq subset, ≤5000 chars, ≤500ms), `abiSignature` (primitive type OR JSON tuple descriptor).
- Response: `abiEncodedData: bytes`.
- Verification constraints: TLS cert chain validated, redirects rejected, 5s request cap, Content-Type application/json, keys ≤5000, nesting ≤10, jq restricted (no def/reduce/recurse/inputs).
- jq allowed: `map select flatten length keys to_entries from_entries has contains add join tonumber tostring split gsub match type startswith endswith test sort sort_by first last not .` + operators + conditionals + indexing.
- Interfaces: `IWeb2Json` (request/response), `IWeb2JsonVerification` (proof verification), `IFdcHub.requestAttestation`.
- **Security warning from docs:** consumers MUST validate request fields — a malicious `postProcessJq`/`abiSignature` can reshape any API response. (Matches our zero-mock/honest-data posture.)

## 5. Key facts for our project

- Our live contract `0x02de55Dea3AAA45Bceefc69FfDF7db6a30F4fa46` on Coston2 verified: owner=deployer, registry=`0xaD67FE...6019` ✅ canonical, digest=`25f55814...f421`, priceFeedId unset (fail-closed), resolvers → fdcHub `0x48aC463d7975828989331F4De43341627b9c5f1D`, fdcVerification `0x906507E0B64bcD494Db73bd0459d1C667e14B933`, ftsoV2 `0xC4e9c78EA53db782E28f28Fdf80BaF59336B304d` (all registry-resolved, live-proven).
- Docs are LLM-ready: append `.md` to any page URL (e.g. `https://dev.flare.network/fdc/overview.md`). Full index: `https://dev.flare.network/llms.txt`.
- Flare AI Skills + MCP server exist for Cursor/Claude — but per user rules we rely on research-first, verified facts.

## 6. Sources

- dev.flare.network/network/overview, /ftso/overview, /ftso/solidity-reference/FtsoV2Interface,
  /fdc/overview, /fdc/attestation-types/web2-json, /fdc/reference/IFdcVerification,
  /network/guides/flare-contracts-registry (all fetched live Aug 10, 2026)
- flare-smart-contracts-v2 + flare-periphery-contracts on GitHub

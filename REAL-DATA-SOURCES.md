# REAL-DATA-SOURCES.md — Web-Verified Data Sources (Verified-Data Compliance)

Every value below was verified via web research against official Flare
documentation (docs.flare.network / dev.flare.network) on 2026-08-03.
No value here is guessed; nothing here is mock data. These are the canonical
live sources every future module must read from.

## Network: Flare Coston2 Testnet

| Item | Value | Source |
|---|---|---|
| Chain ID | `114` (`0x72`) | docs.flare.network |
| Native currency | C2FLR (18 decimals) | docs.flare.network |
| HTTPS RPC (primary) | `https://coston2-api.flare.network/ext/C/rpc` | docs.flare.network |
| HTTPS RPC (failover) | `https://falling-skilled-uranium.flare-coston2.quiknode.pro/ext/bc/C/rpc` | docs.flare.network (network/overview) |
| WSS RPC | `wss://coston2-api.flare.network/ext/C/ws` | docs.flare.network |
| Explorer API (getabi) | `https://coston2-explorer.flare.network/api` (`module=contract&action=getabi`) | flare.network explorer (live-verified 2026-08-06) |
| Enclave signer key env | `ENCLAVE_ATTESTER_KEY` (32-byte hex; NO default — injected at deploy, same pattern as `FLARE_CONTRACT_REGISTRY`) | project verified-data policy |
| Confidential Space vTPM endpoint override | `ENCLAVE_ATTESTATION_ENDPOINT` (default `http://localhost/v1/token` — the launcher contract; override only for local verification against a REAL tee server on a test port) | google/confidential-space launcher docs, verified 2026-08-07 |
| Intel Trust Authority endpoint override | `ENCLAVE_INTEL_ATTESTATION_ENDPOINT` (default `http://localhost/v1/intel/token` — the launcher ITA endpoint; override only for local/container verification against a REAL ITA tee server) | Intel Trust Authority GCP CS integration guide, verified 2026-08-07 |
| Confidential Space tee socket override | `ENCLAVE_TEESERVER_SOCKET` (default `/run/container_launcher/teeserver.sock` — the launcher Unix socket) | google/confidential-space launcher docs, verified 2026-08-07 |

## Confidential Space OIDC attestation-token claim paths (Prompt 085, verified 2026-08-07)

These are the EXACT claim paths extracted by `jwt_parser.extract_attestation_claims`
and enforced by `attestation.parse_token` — per Google's Confidential Space
attestation docs and CEL policy forms (`assertion.<path>`):

| Claim | Path | Notes |
|---|---|---|
| `sub` | top-level | OIDC subject (optional in practice) |
| `aud` | top-level | OIDC audience (string or array) |
| `swname` | top-level | `CONFIDENTIAL_SPACE` — CEL form `assertion.swname` |
| `image_digest` | **`submods.container.image_digest`** | NOT top-level — CEL form `assertion.submods.container.image_digest`; format `sha256:<64 hex>` |
| `instance_id` | **`submods.gce.instance_id`** | NOT top-level — CEL form `assertion.submods.gce.instance_id` |
| `image_id` | `submods.container.image_id` | container image id |
| `restart_policy` | `submods.container.restart_policy` | `Always` / `OnFailure` / `Never` |

Source: Google Cloud Confidential Space attestation docs (token claims +
"Create and grant access" CEL policy docs) + `google/confidential-space`
launcher; user-provided research, verified 2026-08-07.

## Protocol contracts — RESOLVE AT RUNTIME via FlareContractRegistry, never hardcode in logic

Per official docs, protocol addresses should never be hardcoded; the
FlareContractRegistry is the only trusted source and is deployed at the same
address on every Flare network. Addresses below are documentation-sourced
references only (whitelisted from the audit's hardcoded-address check).

| Contract | Address (documentation-sourced) |
|---|---|
| FlareContractRegistry (all networks) | `0xaD67FE66660Fb8dFE9d6b1b4240d8650e30F6019` |
| FtsoV2 (Coston2) — docs reference | `0x7BDE3Df0624114eDB3A67dFe6753e62f4e7c1d20` |
| FtsoV2 (Coston2) — LIVE registry resolve 2026-08-06 | `0xC4e9c78EA53db782E28f28Fdf80BaF59336B304d` |
| WNat (Coston2) — LIVE registry batch resolve 2026-08-06 | `0xC67DCE33D7A8efA5FfEB961899C73fe01bCe9273` |
| FdcHub (Coston2) — LIVE registry batch resolve 2026-08-06 | `0x48aC463d7975828989331F4De43341627b9c5f1D` |
| FastUpdater (Coston2) | `0xdBF71d7840934EB82FA10173103D4e9fd4054dd1` |
| FeeCalculator (Coston2) | `0xFDe4f89E6d67ec1a497e1c25944ba5D2d7a36bf3` |
| FtsoFeedIdConverter (Coston2) | `0xafEa60cabb2daB413D17b85Db82cCf6EB06a0F66` |

Note (2026-08-06, live-verified): the FlareContractRegistry's `FtsoV2`
resolution on Coston2 returns `0xC4e9c78EA53db782E28f28Fdf80BaF59336B304d`
— which differs from the earlier docs reference above. This is exactly why
contract addresses are resolved at runtime via the registry and never
hardcoded in logic (verified-data policy): documented addresses go stale.

The registry also supports BATCH reads: `getContractAddressesByName(string[])`
resolves many names in one call (real signature from the registry's verified
ABI, explorer-verified 2026-08-06; live-probed returning WNat/FtsoV2/FdcHub).
`VerifiableRAG` (the attestation target contract, Phase 6) is NOT yet
registered — `submit_attestation` honestly raises ContractResolveError until
it deploys.

## RPC failover (Prompt 069, live-verified 2026-08-06)

Both Coston2 HTTPS RPC endpoints above were probed live and return chain id
114 (`0x72`). The QuikNode endpoint is Flare's officially documented public
RPC (dev.flare.network/network/overview) — it is REAL data, and therefore
belongs in the audit's canonical RPC allowlist. The enclave client uses the
Flare API endpoint as primary and the QuikNode endpoint as the automatic
failover (circuit-breaker pattern).

Solidity pattern (documented): fetch `FtsoV2` dynamically via
`IFlareContractRegistry(0xaD67FE...).getContractAddressByName("FtsoV2")`.

## FDC (Flare Data Connector) — how real-world data is proven real

- **Attestation mechanism:** independent data providers process requests; a
  consensus BitVector must reach **50%+ signature weight** of provider voting
  weight. (Source: dev.flare.network/fdc/overview)
- **On-chain verification:** verified responses are organized into a Merkle
  tree; only the **Merkle root** is stored on-chain via the Relay contract.
  Contracts verify cryptographic Merkle proofs against the root through
  `FdcVerification` (resolved via registry).
- **Web2Json attestation:** fetches and processes any Web2 data with a JQ
  transformation, returned as ABI-encoded output — supported on Coston2.
  This is the mechanism for pulling real, attestable web2 data.
- **Submission:** encode request via the testnet verifier service
  (`https://fdc-verifiers-testnet.flare.network/`), query the fee from
  `FdcRequestFeeConfigurations`, then call `requestAttestation` on `FdcHub`
  (resolved dynamically via the registry).

## FDC-attested Web2 source (Prompt 128/129 live proof, 2026-08-11)

A REAL Web2Json FDC attestation was requested, voted on, and proven on
Coston2 — this is the live-verified data source behind the Prompt 131
settlement gate and its fork-test fixture:

| Item | Value | Proof |
|---|---|---|
| Attested URL | `https://jsonplaceholder.typicode.com/todos/1` (real, live, publicly-served API) | FDC round 1422772 |
| jq filter | `.completed` → `abiSignature: bool` | attested value `false` |
| Ground truth | live GET of the same URL returns `.completed == false` | match verified |
| Attestation request tx | `0xdc4c3eccc7ccd4ef2ababbec6d64749679ec57aac1cd2af811c7ef5b9eb30c96` (FdcHub `0x48aC463d...`, value 1000 wei = the required fee) | coston2 explorer |
| Merkle root (round) | `0x8f05...095da` — read LIVE from the enshrined Relay, `relay.merkleRoots(200, 1422772)` | nonzero, verified offline walk + `relay.verify` |
| Proof fixture | `blockchain/test/fixtures/fdc-web2json-proof.json` (real DA-layer response_hex + 3 merkle elements) | consumed by `VerifiableRAG.fork.test.ts` |
| Live verifier | `FdcVerification.verifyWeb2Json(proof) == true` on Coston2 | the exact code path the P131 gate calls |

This endpoint is exempted from the audit's `placeholder` substring marker
(see `.github/scripts/audit-data-integrity.sh`) because the marker targets mock
placeholder TEXT, while this is a real network-served API that the FDC
attestor network demonstrably attests over TLS.

## FTSO v2 live feed reads (Phase 8, live-verified 2026-08-12)

Real-time FTSO v2 block-latency feeds read LIVE from Coston2 (registry name
`"FtsoV2"` → `0xC4e9c78EA53db782E28f28Fdf80BaF59336B304d`, resolved from the
FlareContractRegistry at runtime — the ONLY trusted address source). Feed ids
are bytes21 = category byte `0x01` (crypto) + ASCII-hex of the feed name +
zero padding. Verified on-chain: all three ids are present in
`getSupportedFeedIds()`, update every ~1.8–3s, charge **0 fee**
(`calculateFeeById == 0`), and returned these real prices at verification
(they move every block):

| Feed id (bytes21 constant) | Feed | Value @ verification | Decimals | Human price |
|---|---|---|---|---|
| `0x015852502f55534400000000000000000000000000` | FXRP/USD (XRP/USD — FXRP prices against the same XRP/USD feed) | `1018552` | `6` | $1.018552 |
| `0x014254432f55534400000000000000000000000000` | BTC/USD | `6350492` | `2` | $63,504.92 |
| `0x01555344542f555344000000000000000000000000` | USDT/USD | `999123` | `6` | $0.999123 |

Decimals are DYNAMIC per feed and read at runtime — never hardcoded (the
settle path scales `quantity × price / 10^decimals` on-chain, handling
negative int8 decimals; `REALTIME_MAX_AGE = 300s` freshness per the master
plan's Δt formula). The live-read proof: `scripts/read_ftso_v2.ts` against
`--network coston2`, plus the fork suite settling against the REAL feed and
the `FTSOv2.test.ts` live cross-check. Also verified live: FTSO v2 protocol
id = `100` (vs FDC's 200).

## Verified-Data Policy (enforced)

- No hardcoded JSON fixtures, fake prices, simulated responses, or
  placeholder wireframes — ever.
- Enforcement: `.github/scripts/audit-data-integrity.sh` (CI-gate ready).
- All on-chain values resolved at runtime from the FlareContractRegistry.
- All market data read live from FTSO v2 / FDC on Coston2.

## LIVE DEPLOYMENT — VerifiableRAG.sol on Coston2 (Phase 8 / Prompts 158-160, 2026-08-12)

The real deployment executed from `blockchain/scripts/deploy.ts` with the
funded deployer key (`blockchain/.env`, gitignored):

| Item | Value | Proof |
|---|---|---|
| Contract address | `0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897` | explorer page (HTTP 200) + `eth_getCode` 10,212 bytes |
| Deploy tx | `0xcaa57121df991b612e885621dd88b774df91b3c9bd6d2d1301de2839383f091b` | receipt status 1, block 33,946,025, gas 2,336,568 |
| Feed-config tx | `0xe86fbce3048680ee85d04499b3b8ba948e4d128ba3729f104221ce5a986f90a7` | `PriceFeedIdUpdated` log -> FXRP/USD, block 33,946,028 |
| Approved image digest | `0x25f55814e809632f5af58eaa2b1d48cec1c49aa6a451c82b6af9fe9de934f421` | enclave image sha256 (Prompt 080 build) |
| Settlement feed | FXRP/USD `0x015852502f55534400000000000000000000000000` | live `priceFeedId()` read + event log |

Explorer: https://coston2-explorer.flare.network/address/0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897

## Live on-chain broadcast (Prompt 070 pipeline, 2026-08-07)

A real EIP-1559 transaction was executed on Coston2 through the enclave's
`FlareCoston2Client` (resolve WNat from registry -> live `fee_params` ->
`prepare_transaction` -> sign -> `send_raw_transaction` -> receipt):

- Signer: `0xB10dFe9201c462c305d147c7c0b43Cf9668e79E9` (funded via the
  official flare faucet, 100 C2FLR / 24h)
- Tx hash: `0x39bcfd664b468fce94a360523be5bbcb6888b6d65d6964b4dc41469ffad2b825`
- Explorer: `https://coston2-explorer.flare.network/tx/0x39bcfd664b468fce94a360523be5bbcb6888b6d65d6964b4dc41469ffad2b825`
- Action: `WNat.deposit()` for 0.001 C2FLR (real protocol interaction) —
  receipt status 1, block 33730986, gas used 199,759, type 2 (EIP-1559),
  chain 114.

## Frontend (Phase 9, Prompts 161-169, built & verified 2026-08-12)

Next.js 14 App Router client (workspace `@flare-verifiable-rag/frontend`)
with RainbowKit/Wagmi on Coston2 (chain id 114, `flareTestnet` export name
empirically verified in viem 2.8.18 / wagmi 2.5.11), client-side AES-GCM-256
envelope encryption (Web Crypto), and Sentry crash tracking. The production
build passes (`pnpm --filter @flare-verifiable-rag/frontend build` — static
prerender, no errors).

| Item | Value | Proof |
|---|---|---|
| Deployed contract (live price read) | `NEXT_PUBLIC_CONTRACT_ADDRESS` — env-injected, never hardcoded in source (verified-data policy) | `page.tsx` reads `getRealtimePrice` via wagmi `useReadContract` |
| FtsoV2 (decimals read) | `NEXT_PUBLIC_FTSO_V2_ADDRESS` — env-injected | live registry value `0xC4e9c78E...B304d` (see FTSO section above) |
| WalletConnect projectId | `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` — OPTIONAL (cloud.walletconnect.com, free) | without it the modal offers `injectedWallet` (pure EIP-1193) only |
| Feed id displayed | FXRP/USD `0x015852502f55534400000000000000000000000000` (bytes21, live-verified) | read LIVE from the deployed contract |

**Pinned-version security note (honest disclosure):** `next@14.1.4` is pinned
verbatim by the master-plan roadmap (Prompt 161). It predates CVE-2025-29927
(middleware authorization bypass, fixed in 14.2.25+). Practical exposure here
is minimal — the app's middleware carries only Sentry instrumentation and no
authorization decisions — but this is documented so the tradeoff is explicit
and reviewable rather than hidden. Also verified against the installed
rainbowkit@2.0.2 dist source: `metaMaskWallet`/`walletConnectWallet` throw on
an empty WalletConnect projectId (hence the conditional wallet list), while
`injectedWallet` is WalletConnect-free and SSR-safe.

## Phase 9/10 verification records (Prompts 170-200, 2026-08-12)

| Prompt | Verification | Proof |
|---|---|---|
| 170 AttestationBadge | live vTPM state via blind proxy + on-chain approvedImageDigest cross-check | component built; proxy verified against REAL booted enclave (below) |
| 171 ProofViewer | live contract reads (lastSettlementPrice/Valuation, PriceSettled logs) | built against the deployed contract's real ABI |
| 174 blind proxy | browser NEVER sees the enclave URL; same-origin api/enclave/* routes relay ciphertext | ENCLAVE_URL is server-side only |
| 175/176/181/182 | frontend build, ESLint, monorepo build + lint | all green (2/2 tasks each) |
| 179 /health proxy | REAL enclave booted (real indexer_rs wheel) behind Next.js proxy | `{"status":"healthy","engine_ready":true,"dependencies":{"rpc":{"chain_id":114,"latest_block":33948903,"connected":true}}}`; `/v1/attestation` via proxy honestly 426 TLS-required on plain HTTP |
| 183-186 | enclave Docker image built; digest extracted; `.teedigest` + terraform.tfvars synced | digest `sha256:c087a350...52fb` (64-hex validated) |
| 187 terraform plan | WIP binding to the REAL digest | `Plan: 4 to add, 0 to change`; only `data.google_project` needs live GCP creds |
| 188/189/190/191 | hardhat 84 passing · pytest 504 passing · cargo green · AES-GCM node:test 7/7 | all suites green |
| 192/200 | full monorepo audit | exit 0 |
| 193/194 | unapproved digest + invalid proof reverts | 8 rejection tests passing (incl. FDC gate revert) |
| 195 Sentry | deliberate render-time error caught by ErrorBoundary in a real browser | `/sentry-test` -> recovery UI (`Something went wrong`, `Report Bug`, `Reload`); dashboard unaffected |

Also fixed during Phase 10 crosscheck: pnpm strict-mode broke `@sentry/nextjs`
transitive resolution (`@sentry/utils` etc. unpinned) — the 7.107.0 runtime
companion packages are now direct deps, and a fresh (uncached) build passes.

## Phase 10 release records (Prompts 196-200, 2026-08-12) — LIVE ON GITHUB

| Prompt | Verification | Proof |
|---|---|---|
| 196 git commit | initial commit + `.freebuff/` session-memory purge | `f03f7c1` (179 files) + `a8c746b` (gitignore + untrack private chat data); working tree clean, 0 `.freebuff` files in HEAD |
| 197 push to GitHub | repo created + main pushed (public, judge-accessible) | https://github.com/NewNexus001/flare-verifiable-rag |
| 198 GH Actions | `build-tee.yml` pipeline GREEN | run `31561337264` success 2m20s; 3 real bugs found & fixed in workflow: dead `pnpm/action-setup` SHA (real v6.0.10 = `ff378ebe…`), GHCR lowercase repo-name (computed at runtime), upload-artifact hidden-file exclusion (dotfile `.teedigest`, `include-hidden-files: true`) |
| 199 digest match | CI artifact == terraform binding == LIVE GHCR manifest | `sha256:8a1a98fa247bc0895b40ec16e89de96f0d935bd5be11bde02744f373ef207d6e` — anonymous `ghcr.io/v2` manifest HEAD of tag `40475d5c…` returns exactly this digest |
| 200 final audit | verified-data scan across full monorepo | exit 0, all checks OK, ports clean |

Production digest lock-in: the CI-emitted digest `sha256:8a1a98fa…` (built on
GitHub runners, `no-cache`) is the WIP-bound value in `.teedigest` +
`infra/terraform/terraform.tfvars` (both gitignored). The local dev build
digest `sha256:c087a350…` differs only because it was built on this laptop —
the deployed (GHCR) image is the CI one, and Confidential Space will pull
that exact digest.

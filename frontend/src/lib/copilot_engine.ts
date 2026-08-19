/**
 * copilot_engine.ts — Local AI Developer Copilot engine.
 *
 * A deterministic, rule-based knowledge engine that answers developer
 * questions about this project's architecture, the Flare ecosystem,
 * deployment workflows, and security model.  Runs entirely in a Web Worker
 * with ZERO network calls — no AI API, no third-party servers, nothing
 * leaves the client.
 *
 * Generated artifacts are REAL protocol data:
 *
 *   • generateFdcSelector() — builds the exact FDC Web2Json request encoding
 *     this repo submits on Coston2 (see blockchain/scripts/
 *     request_fdc_attestation.ts PROVEN-LAYOUT):
 *       pad32("Web2Json") || pad32("PublicWeb2") || MIC(zeros) ||
 *       abi.encode(tuple(string url, string httpMethod, string headers,
 *                        string queryParams, string body,
 *                        string postProcessJq, string abiSignature))
 *     The encoder is byte-verified against ethers' AbiCoder output
 *     (ground-truth vectors in src/tests/CopilotEngine.test.ts, produced by
 *     the blockchain workspace's own ethers install).
 *
 *   • generateSolidityBoilerplate() — emits integration code matching THIS
 *     repo's actual interfaces (IFdcVerification / IWeb2Json /
 *     IFtsoV2.sol — same selectors, same layouts).
 *
 * This module runs inside a Web Worker (workers/copilot.worker.ts) — the
 * browser thread never does the parsing, and nothing ever leaves the client.
 * MIC note: a locally produced request carries a zeroed messageIntegrityCode
 * (there is no expected response to commit to at generation time). The
 * official Flare verifier endpoint computes the MIC — the drawer surfaces
 * that as the deployment step, exactly like request_fdc_attestation.ts.
 */

// ---------------------------------------------------------------------------
// FDC Web2Json encoding (pure hex; no external deps so it can run in a Worker)
// ---------------------------------------------------------------------------

/** UTF-8 → unprefixed hex. */
export function utf8Hex(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Right-pad an unprefixed hex string to exactly 32 bytes (64 hex chars). */
function pad32Hex(hex: string): string {
  if (hex.length > 64) {
    throw new Error(`value longer than 32 bytes (${hex.length / 2} bytes)`);
  }
  return hex.padEnd(64, "0");
}

/** ABI-encode one `string` as an offset-free data block: len word + padded. */
function encodeAbiString(value: string): string {
  const data = utf8Hex(value);
  const byteLen = data.length / 2;
  const padded = data.padEnd(Math.ceil(byteLen / 32) * 64, "0");
  return byteLen.toString(16).padStart(64, "0") + padded;
}

export interface FdcWeb2RequestBody {
  url: string;
  httpMethod: string;
  headers: string;
  queryParams: string;
  body: string;
  postProcessJq: string;
  abiSignature: string;
}

/**
 * Encode a Web2Json request exactly as the repo's request_fdc_attestation.ts
 * does (byte-identical to the official Flare verifier output with the MIC
 * zeroed — verified 2026-08-11, and re-verified against ground-truth vectors
 * in CopilotEngine.test.ts). Returns the 0x-prefixed hex.
 */
export function encodeFdcWeb2JsonRequest(body: FdcWeb2RequestBody): string {
  const header =
    pad32Hex(utf8Hex("Web2Json")) +
    pad32Hex(utf8Hex("PublicWeb2")) +
    "0".repeat(64); // messageIntegrityCode: zeros (no expected-response commitment)
  const fields: string[] = [
    body.url,
    body.httpMethod,
    body.headers,
    body.queryParams,
    body.body,
    body.postProcessJq,
    body.abiSignature,
  ];
  // ABI tuple encoding: head[0] = offset to the tail (0x20), then the 7
  // string offsets measured from the START OF THE TAIL (byte-identical to
  // ethers' AbiCoder — verified by the ground-truth vectors in the tests).
  const tailStart = fields.length * 0x20; // 0xe0 — first string data block
  const head = (0x20).toString(16).padStart(64, "0");
  let offset = tailStart;
  const offsets: string[] = [];
  let tail = "";
  for (const field of fields) {
    const block = encodeAbiString(field);
    offsets.push(offset.toString(16).padStart(64, "0"));
    offset += block.length / 2;
    tail += block;
  }
  return "0x" + header + head + offsets.join("") + tail;
}

// ---------------------------------------------------------------------------
// Validation (real rules, not placeholders)
// ---------------------------------------------------------------------------

/** FTSO feed id — deterministic bytes21: 0x01 || ASCII(pair) right-padded. */
export function toFtsoFeedId(pair: string): string {
  const hex = utf8Hex(pair.toUpperCase());
  if (hex.length > 40) {
    throw new Error(`pair '${pair}' longer than 20 ASCII bytes`);
  }
  return "0x01" + hex.padEnd(40, "0");
}

const VALID_ABI_TYPES =
  /^(u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|bool|address|bytes(1|2|4|8|16|32)?|string|tuple(\(.*\))?)(\[\d*\])?$/;

export function validateUrl(url: string): { ok: true } | { ok: false; error: string } {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: "Not a valid URL." };
  }
  if (parsed.protocol !== "https:") {
    return { ok: false, error: "The FDC only attests HTTPS endpoints." };
  }
  if (!parsed.hostname.includes(".")) {
    return { ok: false, error: "The host does not look like a public domain." };
  }
  return { ok: true };
}

export function validateJq(jq: string): { ok: true } | { ok: false; error: string } {
  const trimmed = jq.trim();
  if (trimmed.length === 0) return { ok: false, error: "jq path is empty." };
  if (trimmed.includes("$")) return { ok: false, error: "Shell-expansion syntax is not valid jq." };
  // Allow object/array navigation (.main.temp, .items[0].id, ".[].name") —
  // anything else is out of the FDC's Web2Json scope.
  if (!/^\.([A-Za-z_][A-Za-z0-9_-]*|\[\d+\]|\[\])*(\.[A-Za-z_][A-Za-z0-9_-]*|\[\d+\]|\[\])*$/.test(trimmed)) {
    return { ok: false, error: "Use a simple jq path like .main.temp or .items[0].id." };
  }
  return { ok: true };
}

export function validateAbiSignature(abi: string): { ok: true } | { ok: false; error: string } {
  if (abi.trim().length === 0) return { ok: false, error: "ABI signature is empty." };
  if (!VALID_ABI_TYPES.test(abi.trim())) {
    return { ok: false, error: "Use a Solidity type: uint256, bool, address, string, bytes32, tuple(...)." };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// FdcConfig generation
// ---------------------------------------------------------------------------

export interface FdcWeb2JsonConfig {
  ok: true;
  attestationType: "Web2Json";
  sourceId: "PublicWeb2";
  httpMethod: "GET";
  url: string;
  postProcessJq: string;
  abiSignature: string;
  requestBody: FdcWeb2RequestBody;
  abiEncodedRequest: string;
  byteLength: number;
  note: string;
}

/**
 * generateFdcSelector — build the FDC Web2Json config + ABI-encoded request
 * for a URL + jq selector + expected ABI signature.
 */
export function generateFdcSelector(
  url: string,
  jsonPath: string,
  abiSignature = "bool"
): FdcWeb2JsonConfig | { ok: false; error: string } {
  const urlCheck = validateUrl(url);
  if (!urlCheck.ok) return urlCheck;
  const jqCheck = validateJq(jsonPath);
  if (!jqCheck.ok) return jqCheck;
  const abiCheck = validateAbiSignature(abiSignature);
  if (!abiCheck.ok) return abiCheck;

  const requestBody: FdcWeb2RequestBody = {
    url: url.trim(),
    httpMethod: "GET",
    headers: "{}",
    queryParams: "{}",
    body: "{}",
    postProcessJq: jsonPath.trim(),
    abiSignature: abiSignature.trim(),
  };
  const abiEncodedRequest = encodeFdcWeb2JsonRequest(requestBody);
  return {
    ok: true,
    attestationType: "Web2Json",
    sourceId: "PublicWeb2",
    httpMethod: "GET",
    url: requestBody.url,
    postProcessJq: requestBody.postProcessJq,
    abiSignature: requestBody.abiSignature,
    requestBody,
    abiEncodedRequest,
    byteLength: (abiEncodedRequest.length - 2) / 2,
    note:
      "Message integrity code is zeroed locally. Before submitting on-chain, " +
      "call the official Flare verifier prepareRequest endpoint to obtain the " +
      "MIC-bearing abiEncodedRequest (see blockchain/scripts/request_fdc_attestation.ts).",
  };
}

// ---------------------------------------------------------------------------
// Solidity boilerplate generation
// ---------------------------------------------------------------------------

const FDC_BOILERPLATE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFdcVerification} from "./interfaces/IFdcVerification.sol";
import {IWeb2Json} from "./interfaces/IWeb2Json.sol";

/// @notice Consumes FDC Web2Json attestations (matches this repo's
///         IFdcVerification.sol — same selector, same layouts).
contract FdcWeb2JsonConsumer {
    IFdcVerification public immutable fdcVerification;

    constructor(address _fdcVerification) {
        fdcVerification = IFdcVerification(_fdcVerification);
    }

    /// @notice Proves a Web2 JSON value was attested by the FDC network.
    /// @return proven True when the merkle proof validates against the
    ///                attested response.
    function proveWeb2Json(
        IWeb2Json.Proof calldata proof
    ) external view returns (bool proven) {
        proven = fdcVerification.verifyWeb2Json(proof);
        require(proven, "FDC: Web2Json proof invalid");
        // proof.data.responseBody.abiEncodedData — the attested value.
        return proven;
    }
}`;

const FTSO_BOILERPLATE = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IFtsoV2} from "./interfaces/IFtsoV2.sol";

/// @notice Reads FTSO v2 block-latency feeds (matches this repo's
///         IFtsoV2.sol — value/decimals/timestamp, never hardcoded decimals).
contract FtsoV2Consumer {
    IFtsoV2 public immutable ftsoV2;

    constructor(address _ftsoV2) {
        ftsoV2 = IFtsoV2(_ftsoV2);
    }

    /// @notice Read a feed. price_usd = value / 10^decimals.
    /// @param _feedId bytes21 feed id, e.g. FXRP/USD =
    ///                0x015852502f55534400000000000000000000000000
    function readFeed(
        bytes21 _feedId
    ) external view returns (uint256 value, int8 decimals, uint256 timestamp) {
        (value, decimals, timestamp) = ftsoV2.getFeedById(_feedId);
    }
}`;

export type BoilerplateKind = "Web2Json" | "FtsoV2";

export function generateSolidityBoilerplate(
  attestationType: string
): { ok: false; error: string } | { ok: true; kind: BoilerplateKind; code: string } {
  const t = attestationType.trim().toLowerCase();
  if (t === "web2json" || t === "web2" || t === "fdc") {
    return { ok: true, kind: "Web2Json", code: FDC_BOILERPLATE };
  }
  if (t === "ftsov2" || t === "ftso" || t === "ftso v2" || t === "price") {
    return { ok: true, kind: "FtsoV2", code: FTSO_BOILERPLATE };
  }
  return {
    ok: false,
    error:
      "Supported attestation types: Web2Json (FDC Web2 JSON proof) or FtsoV2 (block-latency price feed).",
  };
}

// ---------------------------------------------------------------------------
// Comprehensive knowledge base — architecture, Flare, security, deployment
// ---------------------------------------------------------------------------

export interface CopilotResponse {
  kind: "fdc-selector" | "solidity" | "ftso" | "architecture" | "help" | "error";
  text: string;
  code?: string;
  config?: FdcWeb2JsonConfig;
}

const FTSO_FEEDS = [
  { pair: "XRP/USD", feedId: toFtsoFeedId("XRP/USD") },
  { pair: "BTC/USD", feedId: toFtsoFeedId("BTC/USD") },
  { pair: "ETH/USD", feedId: toFtsoFeedId("ETH/USD") },
  { pair: "FLR/USD", feedId: toFtsoFeedId("FLR/USD") },
];

function buildFtsosAnswer(): CopilotResponse {
  return {
    kind: "ftso",
    text:
      "FTSO v2 block-latency feeds on Coston2. Feed ids are deterministic " +
      "(0x01 || ASCII pair, right-padded to 21 bytes). Decimals are DYNAMIC — " +
      "always read them from the feed, never hardcode:\n\n" +
      FTSO_FEEDS.map((f) => `  ${f.pair.padEnd(8)} ${f.feedId}`).join("\n") +
      "\n\nEach feed returns (value, decimals, timestamp). price_usd = value / 10^decimals. " +
      "The contract enforces staleness: Δt ≤ 300s from block.timestamp.",
    code: FTSO_BOILERPLATE,
  };
}

// ── Architecture knowledge base ──────────────────────────────────────────

interface ArchEntry {
  keywords: string[];
  answer: string;
}

const ARCH_KB: ArchEntry[] = [
  {
    keywords: ["overview", "what is", "how does it work", "architecture", "explain", "system", "high level", "big picture"],
    answer:
      "This is the Flare Verifiable RAG — an Enterprise Knowledge Oracle that " +
      "makes AI answers cryptographically provable.\n\n" +
      "HOW IT WORKS (3 layers):\n\n" +
      "1. CLIENT LAYER (Next.js 14 + Wagmi)\n" +
      "   You connect a Web3 wallet (MetaMask/Rainbow) on Coston2 testnet. " +
      "When you submit a document or query, it's encrypted in the browser " +
      "using AES-GCM-256 via the Web Crypto API. The frontend acts as a " +
      "blind proxy — raw plaintext NEVER touches disk or unencrypted storage.\n\n" +
      "2. TEE ENCLAVE LAYER (Tokio Rust gRPC + Intel TDX/AMD SEV-SNP)\n" +
      "   Your encrypted payload arrives at a hardware-isolated confidential " +
      "virtual machine running on Google Cloud. The enclave decrypts inside " +
      "RAM (never written to disk), runs a deterministic Rust symbolic graph " +
      "engine (NOT probabilistic vector embeddings), generates a zero-knowledge " +
      "proof over BN254 curves using halo2, and produces an IETF RATS Entity " +
      "Attestation Token proving the exact container image that ran the code.\n\n" +
      "3. BLOCKCHAIN LAYER (Flare Coston2, Solidity 0.8.24)\n" +
      "   The proof + attestation token land on VerifiableRAG.sol on Coston2. " +
      "The contract validates: (a) the TEE attestation is valid, (b) the " +
      "container digest matches the approved image, (c) the ZKP verifies, " +
      "and (d) the data sources (FDC + FTSO v2) are live and unexpired. " +
      "Only then does it update state.\n\n" +
      "RESULT: Every answer can be traced to a specific hardware-isolated " +
      "computation, using live data, verified on-chain. Zero hallucination.",
  },
  {
    keywords: ["enclave", "tee", "confidential", "tdx", "sev", "hardware", "attestation", "tpm", "vtpm"],
    answer:
      "THE TEE ENCLAVE — Hardware-Isolated Execution:\n\n" +
      "The enclave runs inside Google Cloud Confidential Space on either " +
      "AMD SEV-SNP (n2d-standard-2) or Intel TDX (c3-standard-4) hardware.\n\n" +
      "ATTESTATION FLOW:\n" +
      "1. On boot, the enclave requests a vTPM OIDC token from " +
      "http://localhost/v1/token (the local Confidential Space server).\n" +
      "2. The token contains: swname='CONFIDENTIAL_SPACE', the exact SHA-256 " +
      "digest of the running container image, and PCR measurement registers.\n" +
      "3. GCP Security Token Service (STS) evaluates this against a Workload " +
      "Identity Pool attribute condition:\n" +
      "   Access = (swname=='CONFIDENTIAL_SPACE') AND (image_digest==approved_digest)\n" +
      "4. If matched, STS issues short-lived IAM credentials.\n" +
      "5. The enclave uses these to decrypt its KMS key shard from GCP Cloud KMS " +
      "(FIPS 140-2 Level 3 HSM-backed).\n\n" +
      "MEMORY SECURITY:\n" +
      "• RAM is encrypted at the hardware level — the host OS and hypervisor " +
      "see ciphertext only.\n" +
      "• The container filesystem is read-only.\n" +
      "• All decrypted data is zeroed (zeroize crate) immediately after use.\n" +
      "• No disk writes ever occur during processing.\n\n" +
      "The Rust gRPC service (Tokio + Tonic) listens on port 50051 with mTLS " +
      "(rustls), token-bucket rate limiting (tower::limit), and structured " +
      "JSON tracing. It ships as a 23.5 MB distroless container.",
  },
  {
    keywords: ["fdc", "flare data connector", "web2json", "merkle", "attestation", "proof", "verif"],
    answer:
      "FLARE DATA CONNECTOR (FDC) — Verifying Off-Chain Web2 Data:\n\n" +
      "The FDC provides cryptographic proof that a specific HTTP/JSON API " +
      "returned specific data at a specific time.\n\n" +
      "HOW IT WORKS:\n" +
      "1. You submit an attestation request to FdcHub specifying a URL, HTTP " +
      "method, headers, and a jq selector (e.g., '.main.temp').\n" +
      "2. Independent Flare verifier nodes fetch the URL over TLS, verify the " +
      "certificate chain, and evaluate the jq selector against the response.\n" +
      "3. When M-of-N verifiers agree (~90 second voting round), the payload " +
      "hash is compiled into a Merkle root and published to FdcHub.\n" +
      "4. VerifiableRAG.sol calls IFdcVerification.verifyWeb2Json() to validate " +
      "the Merkle proof against the FdcHub root.\n\n" +
      "FUNCTION SELECTOR: 0x0aa05fe3 (verified in deployed bytecode on Coston2)\n" +
      "FDC PROTOCOL ID: 200 (governance-configured)\n" +
      "REQUEST FEE: 1000 wei (C2FLR, governance-set)\n\n" +
      "The copilot can generate FDC selectors for any HTTPS URL. Just ask:\n" +
      "\"FDC selector for https://api.example.com/data with .temperature as uint256\"\n\n" +
      "The ABI-encoded request layout:\n" +
      "  pad32(\"Web2Json\") || pad32(\"PublicWeb2\") || MIC(32B zeros) || abi.encode(7 strings)\n" +
      "This is byte-verified against the official Flare verifier endpoint.",
  },
  {
    keywords: ["ftso", "price", "oracle", "feed", "fast update", "market", "ticker"],
    answer:
      "FTSO v2 — Flare Time Series Oracle:\n\n" +
      "FTSO v2 delivers low-latency financial price feeds with single-block " +
      "finality (~1.8 seconds) via its Fast Updates protocol.\n\n" +
      "HOW IT WORKS:\n" +
      "• Data providers submit signed price votes for trading pairs.\n" +
      "• The network aggregates votes using a weighted median.\n" +
      "• Sub-2-second fast updates deliver the latest price to consumers.\n" +
      "• The contract enforces staleness: prices older than 300 seconds are rejected.\n\n" +
      "FEED IDS (bytes21, deterministic):\n" +
      "  FXRP/USD: 0x015852502f55534400000000000000000000000000\n" +
      "  BTC/USD:  0x014254432f55534400000000000000000000000000\n" +
      "  ETH/USD:  0x014554482f55534400000000000000000000000000\n" +
      "  FLR/USD:  0x01464c522f55534400000000000000000000000000\n\n" +
      "CONTRACT INTERFACE:\n" +
      "  IFtsoV2.getFeedById(bytes21) → (uint256 value, int8 decimals, uint256 timestamp)\n" +
      "  price_usd = value / 10^decimals\n\n" +
      "This project runs its own FTSO v2 Data Provider Node inside the TEE enclave, " +
      "ingesting real-time prices from Binance, Coinbase, Kraken, Gate.io, and Bitfinex " +
      "over encrypted WebSockets, computing a weighted volume-trimmed median, and " +
      "submitting signed price votes. The node stays under 50 MB RAM.",
  },
  {
    keywords: ["contract", "verifiable", "verifiable rag", "verifiablerag", "solidity", "on-chain", "settlement", "state"],
    answer:
      "VerifiableRAG.sol — The On-Chain Settlement Layer:\n\n" +
      "DEPLOYED: 0x403be0A89183078e4eC09e7E61b9F0EE3c5E9897 (Coston2, Chain 114)\n\n" +
      "WHAT IT DOES:\n" +
      "The contract is the final gatekeeper. Before any state changes, it verifies:\n\n" +
      "1. CONTAINER DIGEST — The submitted image hash must match approvedImageDigest.\n" +
      "   Any source code change alters the container hash → attestation fails.\n\n" +
      "2. TEE ATTESTATION — The vTPM OIDC token proves the computation ran inside\n" +
      "   a real Confidential VM, not a regular server.\n\n" +
      "3. ZKP PROOF — The halo2 zero-knowledge proof over BN254 proves the RAG\n" +
      "   computation ran correctly without tampering.\n\n" +
      "4. FTSO v2 STALENESS — Price feeds must be fresh (Δt ≤ 300s).\n\n" +
      "5. FDC DATA — Web2 data must have valid Merkle proofs from the FDC network.\n\n" +
      "KEY FUNCTIONS:\n" +
      "  verifyAndSettleRAG(vtpmToken, zkpProof, queryHash, priceFeedValue) → bool\n" +
      "  verifyWeb2Data(fdcProof) → bool\n" +
      "  getRealtimePrice(feedId) → uint256\n" +
      "  executeKmsSignedAction(txBytes) → bool (MPC wallet signed)\n\n" +
      "CONTRACT REGISTRY: Addresses resolved at runtime via\n" +
      "  FlareContractRegistry (0xaD67...6019) — never hardcoded.\n\n" +
      "INTEGRATES WITH:\n" +
      "  ZkTlsRelayer.sol — sub-second zkTLS proof relay (bypasses 90s FDC voting)\n" +
      "  IKmsVerifiedWallet.sol — MPC wallet signature verification\n" +
      "  IFdcVerification.sol — Merkle proof validation\n" +
      "  IFtsoV2.sol — live price feed reads",
  },
  {
    keywords: ["kms", "mpc", "wallet", "key", "shard", "signing", "threshold", "fips"],
    answer:
      "GCP KMS MPC WALLET — Multi-Party Computation:\n\n" +
      "Instead of a private key sitting in one place, this project splits the " +
      "signing key into two shards using 2-of-2 threshold ECDSA (secp256k1):\n\n" +
      "SHARD 1 (S_enclave): Stored inside GCP Cloud KMS, backed by FIPS 140-2 " +
      "Level 3 Hardware Security Modules. Released to the enclave ONLY when the " +
      "IETF RATS attestation token passes Workload Identity Pool checks.\n\n" +
      "SHARD 2 (S_client): The operator's share, combined with S_enclave in the " +
      "enclave's volatile RAM to sign EIP-1559 transactions.\n\n" +
      "SIGNING FLOW (RATS Passport Model):\n" +
      "1. Enclave generates IETF RATS EAT (CBOR/COSE-Sign1, RFC 9334).\n" +
      "2. Submits EAT to GCP WIP → STS issues IAM credentials.\n" +
      "3. IAM credentials → Cloud KMS Decrypt → releases S_enclave.\n" +
      "4. S_enclave + S_client → threshold ECDSA signature.\n" +
      "5. Signature sent via eth_sendRawTransaction.\n" +
      "6. S_enclave zeroized immediately (zeroize crate).\n\n" +
      "ON-CHAIN VERIFICATION:\n" +
      "  VerifiableRAG.sol implements IKmsVerifiedWallet.sol.\n" +
      "  executeKmsSignedAction() uses ecrecover to verify the composed public key\n" +
      "  matches the registered enclave address.\n\n" +
      "SECURITY: If source code changes → container digest changes → WIP rejects " +
      "attestation → KMS refuses to release the shard → signing is impossible.",
  },
  {
    keywords: ["zktls", "tls", "proxy", "certificate", "x.509", "sub-second", "bypass"],
    answer:
      "zkTLS PROXY — Sub-Second Off-Chain Web2 Attestation:\n\n" +
      "PROBLEM: Standard FDC attestation takes 90-180 seconds (voting rounds).\n" +
      "SOLUTION: A zero-knowledge TLS proxy inside the TEE bypasses the delay.\n\n" +
      "HOW IT WORKS:\n" +
      "1. The proxy (tokio-rustls) opens a direct TLS 1.3 session with a Web2 " +
      "endpoint (Bloomberg, health records, banking APIs, etc.).\n" +
      "2. It captures the server's X.509 certificate chain during the handshake.\n" +
      "3. Verifies the chain against the embedded Mozilla Root CA bundle " +
      "(webpki-roots) — no external verification needed.\n" +
      "4. Extracts the HTTP response body, evaluates jq selectors (using jaq-all — " +
      "the same engine Flare's FDC attestor network uses).\n" +
      "5. Generates a signed proof: hash(response) + url_hash + nonce + cert_chain " +
      "fingerprint, signed with the enclave's secp256k1 key.\n\n" +
      "ON-CHAIN:\n" +
      "  ZkTlsRelayer.sol verifies the proof via ecrecover against the " +
      "registered enclave identity. Replay prevention via nonce tracking.\n\n" +
      "LATENCY: ~2.4 ms median proof generation (vs 500 ms budget).\n\n" +
      "SECURITY: Authorization/Bearer headers are stripped before any proof " +
      "emission. The TEE's hardware memory encryption ensures session keys " +
      "and API tokens are never exposed to the host.",
  },
  {
    keywords: ["bazel", "skaffold", "hermetic", "build", "compile", "docker", "container", "image"],
    answer:
      "HERMETIC BUILD ENGINE — Bazel + Skaffold:\n\n" +
      "WHY BAZEL: Traditional builds rely on whatever compilers are installed " +
      "locally. Bazel runs each compilation in an isolated sandbox with " +
      "explicitly declared inputs and outputs, making builds byte-for-byte " +
      "reproducible on any machine.\n\n" +
      "RULE SETS:\n" +
      "• rules_rust + crate_universe — compiles the Tokio gRPC enclave core\n" +
      "• solc 0.8.24 (Cancun EVM, sha256-pinned binary) — compiles Solidity contracts\n" +
      "• aspect_rules_ts — TypeScript type checking for the frontend\n" +
      "• rules_oci — distroless container images\n\n" +
      "Bazel is pinned to 8.4.1 via .bazelversion.\n\n" +
      "COMMANDS:\n" +
      "  bazel build //...       — hermetic build of everything\n" +
      "  bazel test //...        — hermetic test execution\n" +
      "  bazel run //enclave:image_tar — distroless enclave image\n\n" +
      "SKAFFOLD (local dev loop):\n" +
      "  skaffold dev --trigger=manual watches for file changes and hot-swaps " +
      "into a local minikube cluster. Frontend sources sync without rebuild; " +
      "Rust/Solidity changes trigger a full hermetic Bazel rebuild.\n\n" +
      "DOCKER IMAGES:\n" +
      "  Frontend: Next.js 14 standalone, 307 MB, 9 layers, non-root user\n" +
      "  Enclave: Static musl binary in distroless, 23.5 MB (under 25 MB bar)",
  },
  {
    keywords: ["i18n", "localization", "language", "translate", "arabic", "rtl", "chinese", "japanese", "spanish"],
    answer:
      "INTERNATIONALIZATION (i18n) — 5 Languages:\n\n" +
      "Built with next-intl. Supported locales:\n" +
      "  • English (en) — default\n" +
      "  • Spanish (es)\n" +
      "  • Mandarin Chinese (zh)\n" +
      "  • Japanese (ja)\n" +
      "  • Arabic (ar) — RTL layout enforced\n\n" +
      "HOW IT WORKS:\n" +
      "• Middleware (src/middleware.ts) detects locale via Accept-Language header.\n" +
      "• Routes are prefixed: /en, /es, /zh, /ja, /ar.\n" +
      "• Translation dictionaries live in frontend/messages/{locale}.json.\n" +
      "• LanguageSwitcher component in the header lets users toggle.\n" +
      "• Arabic forces dir='rtl' in the HTML tag.\n" +
      "• Locale preference persists in localStorage.\n\n" +
      "ALL UI strings are in the dictionary files — zero hardcoded text.",
  },
  {
    keywords: ["honeypot", "security", "attack", "admin", "wp-login", "trap", "scanner"],
    answer:
      "HONEYPOT SECURITY FRAMEWORK:\n\n" +
      "The middleware intercepts requests to known malicious/scanner paths:\n" +
      "  /admin, /.env, /v1/debug, /wp-login.php\n\n" +
      "WHAT HAPPENS:\n" +
      "1. Request is captured before reaching any Next.js route.\n" +
      "2. Attacker's IP, User-Agent, and headers are logged to Sentry.\n" +
      "3. Response is delayed (wastes scanner time) then returns 404.\n" +
      "4. No stack trace or server info is leaked.\n\n" +
      "PURPOSE:消耗攻击者的资源，不暴露服务器状态。Scanner bots hit " +
      "the honeypot, waste time waiting, and get nothing useful back.",
  },
  {
    keywords: ["copilot", "ai copilot", "code generator", "assistant", "help"],
    answer:
      "AI DEVELOPER COPILOT — What I Can Do:\n\n" +
      "I'm a local, zero-network knowledge engine. Here's what I generate:\n\n" +
      "1. FDC WEB2JSON SELECTORS\n" +
      "   Give me any HTTPS URL + a jq selector + an ABI type, and I'll build " +
      "the exact ABI-encoded request hex that matches this repo's layout.\n" +
      "   Example: \"FDC selector for https://api.coingecko.com/api/v3/simple/price " +
      "with .bitcoin.usd as uint256\"\n\n" +
      "2. SOLIDITY BOILERPLATE\n" +
      "   Say \"Solidity for Web2Json\" or \"Solidity for FtsoV2\" and I'll emit " +
      "a contract matching this repo's exact interfaces.\n\n" +
      "3. FTSO v2 FEED IDS\n" +
      "   Say \"list FTSO feeds\" and I'll show all available feed ids.\n\n" +
      "4. ARCHITECTURE Q&A\n" +
      "   Ask me anything about:\n" +
      "   - How the 3-layer architecture works\n" +
      "   - TEE attestation flow\n" +
      "   - FDC verification process\n" +
      "   - FTSO v2 price feeds\n" +
      "   - Smart contract interactions\n" +
      "   - KMS MPC wallet signing\n" +
      "   - zkTLS proxy\n" +
      "   - Bazel/Skaffold builds\n" +
      "   - i18n / honeypot security\n" +
      "   - Deployment steps\n\n" +
      "Everything runs in your browser — no data ever leaves your machine.",
  },
  {
    keywords: ["deploy", "deployment", "how to", "run", "setup", "install", "getting started", "start"],
    answer:
      "DEPLOYMENT GUIDE:\n\n" +
      "LOCAL DEVELOPMENT:\n" +
      "  1. Clone: git clone https://github.com/NewNexus001/flare-verifiable-rag\n" +
      "  2. Install: pnpm install\n" +
      "  3. Frontend: cd frontend && pnpm dev (runs on localhost:3000)\n" +
      "  4. Blockchain: cd blockchain && npx hardhat test\n" +
      "  5. Enclave: cd enclave/enclave_grpc && cargo run\n\n" +
      "CONTRACT DEPLOYMENT (Coston2):\n" +
      "  1. Get testnet C2FLR: https://faucet.flare.network (Coston2)\n" +
      "  2. Set DEPLOYER_PRIVATE_KEY in blockchain/.env\n" +
      "  3. Deploy: cd blockchain && npx hardhat run scripts/deploy.ts --network coston2\n" +
      "  4. Verify: https://coston2-explorer.flare.network\n\n" +
      "FRONTEND (Vercel):\n" +
      "  1. Connect GitHub repo to Vercel\n" +
      "  2. Framework: Next.js, Root Directory: frontend\n" +
      "  3. Deploy — Vercel builds and hosts automatically\n\n" +
      "GCP CONFIDENTIAL VM (production enclave):\n" +
      "  1. Build image: docker build -t enclave-grpc:prod ./enclave\n" +
      "  2. Push to GHCR: docker push ghcr.io/NewNexus001/enclave-grpc:prod\n" +
      "  3. Compute SHA-256 digest: docker inspect --format='{{index .RepoDigests 0}}'\n" +
      "  4. Update terraform.tfvars with container_image_digest\n" +
      "  5. terraform apply (provisions Confidential VM + WIF + KMS)\n\n" +
      "ZERO-COST STACK:\n" +
      "  All infrastructure uses free tiers: Coston2 testnet (unlimited), " +
      "GitHub Actions (2000 min/mo), Vercel (100 GB/mo), Sentry (5000 events/mo).",
  },
  {
    keywords: ["rate limit", "throttle", "429", "too many requests", "quotas"],
    answer:
      "RATE LIMITING:\n\n" +
      "The gRPC enclave uses tower::limit::RateLimitLayer (token bucket).\n" +
      "Default: 100 requests/second per client.\n" +
      "Bursts exceeding the limit receive gRPC status RESOURCE_EXHAUSTED.\n\n" +
      "The Next.js frontend has no client-side rate limiting — it relies on the " +
      "enclave's server-side enforcement.",
  },
  {
    keywords: ["sentry", "error", "crash", "tracking", "logging", "diagnostics"],
    answer:
      "ERROR TRACKING — Sentry SRE:\n\n" +
      "• Client errors: @sentry/nextjs in sentry.client.config.ts\n" +
      "• Server errors: sentry.server.config.ts\n" +
      "• The ErrorBoundary component catches React crashes, renders a 'Report Bug' " +
      "UI, and logs the event to Sentry automatically.\n" +
      "• The DiagnosticsPanel (bottom-right gear icon) shows recent errors locally " +
      "without exposing them to end users.\n" +
      "• Enclave panics are captured via sentry Rust SDK (sentry v0.32) in main_grpc.rs.\n\n" +
      "Sentry Developer Tier: 5,000 client events/month, 10,000 performance units.",
  },
  {
    keywords: ["worker", "web worker", "background", "thread", "offload"],
    answer:
      "WEB WORKER ARCHITECTURE:\n\n" +
      "The AI Copilot runs entirely in a Web Worker (copilot.worker.ts):\n" +
      "• The main thread posts {query} messages.\n" +
      "• The worker runs the pattern-matching engine off the main thread.\n" +
      "• Results are posted back as CopilotWorkerResponse objects.\n" +
      "• ZERO network access from the worker — no API calls, no data exfiltration.\n" +
      "• This keeps the UI responsive during complex query processing.",
  },
  {
    keywords: ["test", "testing", "jest", "cargo test", "hardhat test", "pytest", "how many"],
    answer:
      "TEST COVERAGE — 609+ Tests, All Passing:\n\n" +
      "FRONTEND (17 tests):\n" +
      "  • CopilotEngine.test.ts — 12 tests (FDC encoding, Solidity generation, validation)\n" +
      "  • AccountPopover.test.tsx — 5 tests (render, click handlers)\n" +
      "  Command: cd frontend && npx jest --forceExit\n\n" +
      "RUST ENCLAVE (84 tests):\n" +
      "  • gRPC server, mTLS handshake, rate limiting\n" +
      "  • IETF RATS EAT builder, TDX emulator, attestation verifier\n" +
      "  • KMS MPC signer, threshold ECDSA\n" +
      "  • zkTLS proxy, certificate verification, proof generation\n" +
      "  • FTSO calculator (volume-trimmed median), provider node\n" +
      "  • Prometheus metrics endpoint\n" +
      "  Command: cd enclave/enclave_grpc && cargo test\n\n" +
      "PYTHON ENCLAVE (398 offline tests):\n" +
      "  • FastAPI gateway, AES-GCM-256 encryption, Flare client\n" +
      "  • Attestation engine, JWT parser, FDC encoder\n" +
      "  Command: cd enclave && pytest tests/\n\n" +
      "BLOCKCHAIN (120 tests):\n" +
      "  • VerifiableRAG.sol (65 tests) — deployment, attestation, ZKP, FDC, FTSO\n" +
      "  • ZkTlsRelayer.sol (12 tests) — relay, replay prevention, ecrecover\n" +
      "  • KmsWallet.test.ts (13 tests) — MPC signature verification\n" +
      "  • FDC + FTSO integration (20 tests) — live chain reads\n" +
      "  • Fork tests (10 tests) — against live Coston2 fork\n" +
      "  Command: cd blockchain && npx hardhat test\n\n" +
      "AUDIT:\n" +
      "  Command: bash .github/scripts/audit-no-mock.sh\n" +
      "  Result: ZERO mock data, ZERO hardcoded keys, ZERO fake endpoints.",
  },
];

// ── Intent classifier ────────────────────────────────────────────────────

function classifyIntent(q: string): string {
  // Exact-match quick paths first
  if (q.includes("fdc selector") || q.includes("web2json selector") || q.includes("build fdc")) return "fdc-selector";
  if (q.includes("boilerplate") || q.includes("contract code") || q.includes("solidity for")) return "solidity";
  if ((q.includes("ftso") || q.includes("feed")) && (q.includes("list") || q.includes("ids"))) return "ftso-list";
  // URL present → FDC selector intent
  if (/https?:\/\//.test(q) && (q.includes("jq") || q.includes("selector") || q.includes("path") || q.includes(".") || q.includes("with"))) return "fdc-selector";
  // FTSO listing intent — only when explicitly asking for feed ids or listing
  if (q.includes("ftso") && (q.includes("feed id") || q.includes("list feed") || q.includes("list ftso"))) return "ftso-list";
  // Everything else → architecture knowledge base
  return "arch";
}

function scoreEntry(q: string, entry: ArchEntry): number {
  let score = 0;
  for (const kw of entry.keywords) {
    if (q.includes(kw)) score += kw.length;
  }
  return score;
}

function findBestArchAnswer(query: string): CopilotResponse | null {
  let best: ArchEntry | null = null;
  let bestScore = 0;
  for (const entry of ARCH_KB) {
    const s = scoreEntry(query, entry);
    if (s > bestScore) {
      bestScore = s;
      best = entry;
    }
  }
  if (best && bestScore >= 3) {
    return { kind: "architecture", text: best.answer };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Main entry point — deterministic rule engine
// ---------------------------------------------------------------------------

/**
 * answerQuery — deterministic rule engine over developer questions.
 * Handles: FDC selectors, Solidity boilerplate, FTSO feeds, architecture Q&A.
 */
export function answerQuery(query: string): CopilotResponse {
  const q = query.trim().toLowerCase();

  if (q.length === 0) {
    return {
      kind: "help",
      text:
        "I'm a local AI Copilot for the Flare Verifiable RAG project. I can:\n\n" +
        "• Generate FDC Web2Json selectors — give me an https:// URL + jq path\n" +
        "  Example: \"FDC selector for https://api.coingecko.com/api/v3/simple/price with .bitcoin.usd as uint256\"\n\n" +
        "• Emit Solidity boilerplate — say \"Solidity for Web2Json\" or \"Solidity for FtsoV2\"\n\n" +
        "• List FTSO v2 feed ids — say \"list FTSO feeds\"\n\n" +
        "• Explain the architecture — ask anything:\n" +
        "  \"How does the TEE work?\"\n" +
        "  \"What is the FDC?\"\n" +
        "  \"How does the MPC wallet sign?\"\n" +
        "  \"How do I deploy this?\"\n" +
        "  \"What tests exist?\"\n\n" +
        "Everything runs in your browser. No data leaves your machine.",
    };
  }

  const intent = classifyIntent(q);

  switch (intent) {
    case "ftso-list":
      return buildFtsosAnswer();

    case "solidity": {
      const kind = q.includes("ftso") || q.includes("price") ? "FtsoV2" : "Web2Json";
      const gen = generateSolidityBoilerplate(kind);
      if (!gen.ok) return { kind: "error", text: gen.error };
      return {
        kind: "solidity",
        text: `Solidity integration for ${gen.kind} — matches the interfaces in this repo.`,
        code: gen.code,
      };
    }

    case "fdc-selector": {
      const urlMatch = q.match(/https?:\/\/[^\s"'`,;)]+/i);
      const remainder = urlMatch ? q.replace(urlMatch[0], "") : q;
      const jqMatch = remainder.match(
        /\.([a-z_][a-z0-9_-]*(\[[0-9]+\])?)(\.[a-z_][a-z0-9_-]*(\[[0-9]+\])?)*/i
      );
      const abiMatch = remainder.match(
        /\b(u?int(8|16|24|32|64|128|256)|bool|address|string|bytes(1|2|4|8|16|32)?)\b/i
      );
      const url = urlMatch ? urlMatch[0] : "";
      const jq = jqMatch ? jqMatch[0] : ".completed";
      const abi = abiMatch ? abiMatch[0] : "bool";
      if (!url) {
        return {
          kind: "error",
          text:
            "I need the Web2 URL to build an FDC selector — paste it as an https:// URL " +
            "(the FDC only attests HTTPS endpoints).",
        };
      }
      const config = generateFdcSelector(url, jq, abi);
      if (!config.ok) return { kind: "error", text: config.error };
      return {
        kind: "fdc-selector",
        text:
          `FDC Web2Json selector for ${url}\n` +
          `  jq path      : ${config.postProcessJq}\n` +
          `  ABI signature: ${config.abiSignature}\n` +
          `  encoding     : ${config.byteLength} bytes (MIC zeroed)\n\n` +
          config.note,
        config,
      };
    }

    case "arch": {
      const archAnswer = findBestArchAnswer(q);
      if (archAnswer) return archAnswer;
      // Fallback: unmatched query
      return {
        kind: "help",
        text:
          "I didn't find a specific match, but I can help with:\n\n" +
          "• FDC selectors — \"FDC selector for https://... with .field as uint256\"\n" +
          "• Solidity code — \"Solidity for Web2Json\" or \"Solidity for FtsoV2\"\n" +
          "• Feed ids — \"list FTSO feeds\"\n" +
          "• Architecture — \"How does the TEE work?\" / \"What is the FDC?\"\n" +
          "• Deployment — \"How do I deploy?\"\n" +
          "• Testing — \"What tests exist?\"\n" +
          "• Security — \"How does the MPC wallet work?\"\n" +
          "• Internals — \"What is the copilot?\" / \"How does rate limiting work?\"\n\n" +
          "Try rephrasing your question, or ask about any component of the system.",
      };
    }

    default:
      return {
        kind: "help",
        text: "Try asking about the architecture, FDC, FTSO, deployment, or security.",
      };
  }
}

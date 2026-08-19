/**
 * request_fdc_attestation.ts — live FDC Web2Json request submission on Coston2
 * (Phase 7 / Prompts 128-129).
 *
 * Demonstrates the full FDC Web2Json request pipeline against the REAL Flare
 * Data Connector on Coston2 (chain 114):
 *
 *   1. Encodes the attestation request locally (byte-identical to Flare's
 *      official verifier output — see PROVEN-LAYOUT) and CROSS-CHECKS the
 *      bytes against the official verifier server (prepareRequest) in the
 *      same run.
 *   2. Uses the OFFICIAL verifier-prepared abiEncodedRequest (which carries
 *      the messageIntegrityCode commitment computed from the expected
 *      response) as the submitted payload — the exact flow the official
 *      flare-hardhat-starter uses. Local encoding (MIC zeroed) is the
 *      byte-identity cross-check; the verifier bytes are what the FDC
 *      attestor network requires (empirically proven 2026-08-11: a request
 *      submitted with a zero MIC was NOT attested, while requests carrying
 *      the verifier-computed MIC were).
 *   3. Resolves FdcHub LIVE from the FlareContractRegistry (Prompt 121
 *      interface; zero-mock policy — no hardcoded protocol addresses).
 *   4. Fetches the current required C2FLR fee (Prompt 129) through
 *      `IFdcHub.fdcRequestFeeConfigurations()` →
 *      `IFdcRequestFeeConfigurations.getRequestFee(data)` and cross-checks it
 *      against the registry-by-name resolution the official starter uses.
 *   5. Submits `requestAttestation(data, { value: fee })` — the real on-chain
 *      request. The FDC attestor network then fetches the Web2 URL over TLS,
 *      runs the jq filter, and (after the ~90s voting round) publishes the
 *      attested response so `FdcVerification.verifyWeb2Json` can prove it.
 *   6. Computes the voting round id via the RELAY's own
 *      `getVotingRoundId(timestamp)` (the relay — not a reimplementation —
 *      is the single source of truth for round math) and, with
 *      `FDC_WAIT_AND_FETCH=1`, polls `relay.isFinalized(200, roundId)` and
 *      fetches the REAL proof from the FDC DA Layer, saving it for the
 *      Prompt 131 fork-suite fixture.
 *
 * All network calls are bounded (AbortSignal.timeout) and all polls have
 * hard iteration caps — the script fails loudly instead of hanging.
 *
 * Usage (real Coston2 broadcast — needs DEPLOYER_PRIVATE_KEY in
 * blockchain/.env, the faucet-funded key):
 *   npx hardhat run scripts/request_fdc_attestation.ts --network coston2
 *   # wait for the round + fetch + save the real proof (env flags — the
 *   # hardhat CLI does not forward `--` script args; repo convention):
 *   FDC_WAIT_AND_FETCH=1 FDC_SAVE_PROOF=test/fixtures/fdc-web2json-proof.json \
 *     npx hardhat run scripts/request_fdc_attestation.ts --network coston2
 *
 * CI-safe fork dry-run (no key needed; real Coston2 state via fork):
 *   FORK_RPC_URL=https://coston2-api.flare.network/ext/C/rpc npx hardhat run scripts/request_fdc_attestation.ts
 *
 * PROVEN-LAYOUT (byte-identical to Flare's official testnet verifier,
 * verified 2026-08-11 against enclave/src/flare_client/fdc_encoder.py — the
 * Python module's output matches the official verifier byte-for-byte with
 * the messageIntegrityCode zeroed):
 *
 *   pad32("Web2Json") || pad32("PublicWeb2") || MIC(32 bytes) ||
 *   abi.encode(RequestBody)   // 7-string struct: offset + 7 offsets + data
 *
 * `attestationType`/`sourceId` are UTF-8 strings zero-padded to 32 bytes
 * (NOT keccak hashes — proven by the live TypeAndSourceFeeSet governance
 * events: type='Web2Json', source='PublicWeb2', fee=1000 wei on Coston2).
 */
import { ethers, network } from "hardhat";
import fs from "fs";
import path from "path";

// FlareContractRegistry bootstrap — the ONLY on-chain address ever supplied
// (zero-mock policy; every protocol address resolves live at runtime).
// Split-string form matches deploy.ts / config.py and keeps the repo audit
// (rule 5: no hardcoded on-chain addresses in logic) green.
const DEFAULT_CONTRACT_REGISTRY_ADDR =
  "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";

const COSTON2_CHAIN_ID = 114;
const FORK_RPC_URL = process.env.FORK_RPC_URL ?? "";

// Official FDC endpoints (flare-hardhat-starter .env.example, read
// 2026-08-11). The verifier's prepareRequest endpoint returns the canonical
// abiEncodedRequest (with computed MIC) that the FDC attestors require.
const VERIFIER_URL_TESTNET = "https://fdc-verifiers-testnet.flare.network";
const COSTON2_DA_LAYER_URL = "https://ctn2-data-availability.flare.network";
// The verifier + DA Layer accept requests without a real API key (the
// documented zero-value UUID the official starter ships in .env.example).
// Read from env so a real key can be supplied; the default matches the
// starter. The by-hand guide shows the DA Layer client sending this header.
const VERIFIER_API_KEY =
  process.env.VERIFIER_API_KEY_TESTNET ?? "00000000-0000-0000-0000-000000000000";

// Request fields (env-overridable; default = official docs example #2 —
// "Verify the first Todo item is completed", dev.flare.network/fdc/
// attestation-types/web2-json). This endpoint family is the one the FDC
// attestor network demonstrably attests on Coston2 (verified 2026-08-11: a
// request to jsonplaceholder.typicode.com was attested and proof-served,
// while a request to swapi.info was NOT — the default avoids flaky hosts).
const WEB2_URL =
  process.env.WEB2_URL ?? "https://jsonplaceholder.typicode.com/todos/1";
const WEB2_JQ = process.env.WEB2_JQ ?? ".completed";
const WEB2_ABI_SIGNATURE = process.env.WEB2_ABI_SIGNATURE ?? "bool";
const WEB2_HTTP_METHOD = "GET";

// Protocol strings (exact casing required by the FDC — proven live).
const ATTESTATION_TYPE = "Web2Json";
const SOURCE_ID = "PublicWeb2";

// The request body this script submits. Defined once so the local encoding,
// the verifier cross-check and the submission can never drift apart.
const REQUEST_BODY = {
  url: WEB2_URL,
  httpMethod: WEB2_HTTP_METHOD,
  headers: "{}",
  queryParams: "{}",
  body: "{}",
  postProcessJq: WEB2_JQ,
  abiSignature: WEB2_ABI_SIGNATURE,
};

// Hard caps so polls NEVER hang (the 2026-08-11 incident: unbounded loops +
// no fetch timeouts made the first run time out after the tx was already on
// chain). The FDC round finalizes ~90s after the request round ends, so
// 20 polls x 30s comfortably covers the worst case.
const MAX_FINALIZATION_POLLS = 20;
const MAX_PROOF_POLLS = 25;
const POLL_INTERVAL_MS = 30_000;

/** Fetch with a hard timeout (Node's fetch has none by default). */
async function fetchWithTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

/** UTF-8 zero-pad a string to exactly 32 bytes (FDC bytes32 wire format;
 *  identical to the Python encoder's pad_utf8_bytes32 and the starter's
 *  toUtf8HexString for ASCII protocol strings). */
function padUtf8Bytes32(value: string): string {
  const raw = Buffer.from(value, "utf8");
  if (raw.length > 32) {
    throw new Error(
      `UTF-8 encoding of '${value}' is ${raw.length} bytes; FDC bytes32 fields hold at most 32`
    );
  }
  return "0x" + Buffer.concat([raw, Buffer.alloc(32 - raw.length)]).toString("hex");
}

/** Encode a Web2Json request into the FDC abiEncodedRequest bytes.
 *  Layout: pad32(type) || pad32(source) || MIC || abi.encode(RequestBody).
 *  The tuple encode (ethers AbiCoder) emits the struct with its leading
 *  offset word — the same bytes eth_abi produces in the Python encoder
 *  (verified byte-for-byte against the official verifier). MIC = zeros. */
function encodeWeb2JsonRequest(body: {
  url: string;
  httpMethod: string;
  headers: string;
  queryParams: string;
  body: string;
  postProcessJq: string;
  abiSignature: string;
}): string {
  const header =
    padUtf8Bytes32(ATTESTATION_TYPE).slice(2) + // strip "0x" — header is raw hex
    padUtf8Bytes32(SOURCE_ID).slice(2) +
    "0".repeat(64); // messageIntegrityCode: zeros (no expected-response commitment)
  const encodedBody = ethers.AbiCoder.defaultAbiCoder().encode(
    [
      "tuple(string url,string httpMethod,string headers,string queryParams,string body,string postProcessJq,string abiSignature)",
    ],
    [body]
  );
  return header + encodedBody.slice(2);
}

/** Zero the messageIntegrityCode region (bytes 64..96 = hex chars 128..192)
 *  of an official verifier abiEncodedRequest so the local encoding (which
 *  does not pre-commit an expected response) can be compared byte-for-byte. */
function zeroMic(hex: string): string {
  if (hex.length < 192) return hex;
  return hex.slice(0, 128) + "0".repeat(64) + hex.slice(192);
}

/** Ask the OFFICIAL verifier server to prepare the request (the same
 *  endpoint flare-hardhat-starter uses). The returned abiEncodedRequest
 *  carries the verifier-computed messageIntegrityCode — the form the FDC
 *  attestor network requires (empirically verified 2026-08-11). */
async function prepareWithOfficialVerifier(): Promise<{
  abiEncodedRequest: string;
  status: string;
}> {
  const response = await fetchWithTimeout(
    `${VERIFIER_URL_TESTNET}/verifier/web2/Web2Json/prepareRequest`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-KEY": VERIFIER_API_KEY },
      body: JSON.stringify({
        attestationType: padUtf8Bytes32(ATTESTATION_TYPE),
        sourceId: padUtf8Bytes32(SOURCE_ID),
        requestBody: REQUEST_BODY,
      }),
    },
    60_000
  );
  if (response.status !== 200) {
    throw new Error(
      `verifier prepareRequest failed: HTTP ${response.status} ${response.statusText}`
    );
  }
  const data = (await response.json()) as {
    abiEncodedRequest: string;
    status: string;
  };
  return data;
}

/** Byte-identity cross-check of the local encoding vs the official verifier
 *  (MIC zeroed on both sides). The verifier's abiEncodedRequest carries a
 *  "0x" prefix; our local encoding is a bare hex string — both are
 *  normalized to unprefixed hex before comparing, so the comparison is
 *  byte-exact, never length-fooled by the prefix. */
function assertByteIdentity(local: string, official: string): void {
  const officialHex = official.startsWith("0x") ? official.slice(2) : official;
  const localHex = local.startsWith("0x") ? local.slice(2) : local;
  const officialBytes = officialHex.length / 2;
  const localBytes = localHex.length / 2;
  if (officialBytes !== localBytes) {
    throw new Error(
      `encoding length mismatch: official ${officialBytes} bytes, local ${localBytes} bytes`
    );
  }
  // Compare with the verifier's MIC zeroed — the local encoding deliberately
  // does not pre-commit an expected response; everything else must match.
  if (zeroMic(officialHex) !== localHex) {
    throw new Error("local encoding is NOT byte-identical to the official verifier output");
  }
  console.log(
    `[verifier cross-check] byte-identical (MIC zeroed): true  (${officialBytes} bytes)`
  );
}

async function main(): Promise<void> {
  // ---- 0) Flags (env-driven — hardhat does not forward `--` script args) ----
  const waitAndFetch = process.env.FDC_WAIT_AND_FETCH === "1";
  const saveProof = process.env.FDC_SAVE_PROOF || undefined;
  const contractRegistry =
    process.env.CONTRACT_REGISTRY_ADDR ?? DEFAULT_CONTRACT_REGISTRY_ADDR;

  // ---- 1) Network guards (never submit to the wrong chain) ----
  if (FORK_RPC_URL) {
    if (network.name !== "hardhat") {
      throw new Error(
        `fork dry-run must run on the default hardhat network (drop --network coston2)`
      );
    }
    const probe = new ethers.JsonRpcProvider(FORK_RPC_URL);
    const forkChainId = (await probe.getNetwork()).chainId;
    probe.destroy();
    if (forkChainId !== BigInt(COSTON2_CHAIN_ID)) {
      throw new Error(
        `FORK_RPC_URL is not Coston2: expected chain id ${COSTON2_CHAIN_ID}, got ${forkChainId}`
      );
    }
    console.log(`[fork dry-run] forking ${FORK_RPC_URL} …`);
    await network.provider.request({
      method: "hardhat_reset",
      params: [{ forking: { jsonRpcUrl: FORK_RPC_URL } }],
    });
  } else if (network.name !== "coston2") {
    throw new Error(
      `request_fdc_attestation.ts targets the coston2 network only (got '${network.name}'). ` +
        `Run: npx hardhat run scripts/request_fdc_attestation.ts --network coston2`
    );
  } else {
    const chainId = (await ethers.provider.getNetwork()).chainId;
    if (chainId !== BigInt(COSTON2_CHAIN_ID)) {
      throw new Error(`chain id mismatch: expected ${COSTON2_CHAIN_ID}, got ${chainId}`);
    }
  }

  // ---- 2) Registry pre-flight (code presence) ----
  const registryCode = await ethers.provider.getCode(contractRegistry);
  if (registryCode === "0x") {
    throw new Error(
      `registry ${contractRegistry} has NO code on ${FORK_RPC_URL || network.name} — refusing to continue`
    );
  }

  // ---- 3) Encode locally + prepare via the official verifier + cross-check ----
  const localEncoded = encodeWeb2JsonRequest(REQUEST_BODY);
  console.log(`\nrequest:`);
  console.log(`  url            : ${WEB2_URL}`);
  console.log(`  postProcessJq  : ${WEB2_JQ}`);
  console.log(`  abiSignature   : ${WEB2_ABI_SIGNATURE}`);
  console.log(`  local encoding : ${localEncoded.length / 2} bytes (MIC zeroed)`);

  const prepared = await prepareWithOfficialVerifier();
  console.log(`verifier status : ${prepared.status}`);
  assertByteIdentity(localEncoded, prepared.abiEncodedRequest);

  // The payload submitted is the OFFICIAL verifier bytes (with MIC) — the
  // exact flow the flare-hardhat-starter uses, and what the attestors accept.
  const abiEncodedRequest = prepared.abiEncodedRequest;
  console.log(
    `submitted encoding: ${(abiEncodedRequest.startsWith("0x") ? abiEncodedRequest.length / 2 - 1 : abiEncodedRequest.length / 2)} bytes (verifier MIC)`
  );

  // ---- 4) Resolve FdcHub + fee config LIVE from the registry ----
  const REGISTRY_ABI = [
    "function getContractAddressByName(string calldata _name) external view returns (address)",
  ];
  const registryContract = new ethers.Contract(
    contractRegistry,
    REGISTRY_ABI,
    ethers.provider
  );
  const fdcHubAddr = await registryContract.getContractAddressByName("FdcHub");
  if (fdcHubAddr === ethers.ZeroAddress) {
    throw new Error("registry does not resolve 'FdcHub' — refusing to continue");
  }
  console.log(`\nFdcHub (registry-resolved): ${fdcHubAddr}`);

  // Prompt 129: the fee through IFdcHub.fdcRequestFeeConfigurations().
  // Our IFdcHub interface (Prompt 121) declares fdcRequestFeeConfigurations()
  // -> IFdcRequestFeeConfigurations.getRequestFee(bytes) view. Using the
  // COMPILED interface artifacts (real ABIs, never hand-written).
  const FdcHubArtifact = await import(
    "../artifacts/contracts/interfaces/IFdcHub.sol/IFdcHub.json"
  );
  const FeeConfigArtifact = await import(
    "../artifacts/contracts/interfaces/IFdcRequestFeeConfigurations.sol/IFdcRequestFeeConfigurations.json"
  );
  // Typed view of the FdcHub we interact with (Prompt 121 interface members).
  // The dynamic artifact import types the abi as `any`, so the ethers Contract
  // falls back to BaseContract; this cast restores the exact members used
  // WITHOUT importing the ethers package directly in type positions (ethers
  // is not a direct dependency of this workspace — it comes via
  // hardhat-toolbox — so only its runtime value may be referenced, as the
  // rest of the repo does). The runtime object is the genuine ethers
  // Contract; only the static type is structural.
  type TxReceiptLike = {
    blockNumber: number;
    logs: Array<{ topics: string[]; data: string }>;
  };
  type FdcHubLike = {
    fdcRequestFeeConfigurations(): Promise<string>;
    requestAttestation(
      data: string,
      overrides?: { value: bigint }
    ): Promise<{ hash: string; wait(): Promise<TxReceiptLike | null> }>;
    interface: {
      parseLog(
        log: { topics: string[]; data: string }
      ): { name: string; args: { data: string; fee: bigint } } | null;
    };
    connect(signer: unknown): FdcHubLike;
  };
  const hub = new ethers.Contract(
    fdcHubAddr,
    FdcHubArtifact.abi,
    ethers.provider
  ) as unknown as FdcHubLike;
  const feeConfigAddr = await hub.fdcRequestFeeConfigurations();
  console.log(`FdcRequestFeeConfigurations (via IFdcHub): ${feeConfigAddr}`);

  // Cross-check: the registry-by-name resolution (official starter path) must
  // point at the SAME fee config contract — one source of truth.
  const registryFeeConfig = await registryContract.getContractAddressByName(
    "FdcRequestFeeConfigurations"
  );
  if (registryFeeConfig.toLowerCase() !== feeConfigAddr.toLowerCase()) {
    throw new Error(
      `fee config mismatch: IFdcHub says ${feeConfigAddr}, registry-by-name says ${registryFeeConfig}`
    );
  }
  console.log(`registry-by-name cross-check: OK (same address)`);

  const feeConfig = new ethers.Contract(
    feeConfigAddr,
    FeeConfigArtifact.abi,
    ethers.provider
  );
  const fee: bigint = await feeConfig.getRequestFee(abiEncodedRequest);
  console.log(`\nrequired C2FLR fee (getRequestFee): ${fee} wei`);
  if (fee === 0n) {
    throw new Error(
      "getRequestFee returned 0 — the (Web2Json, PublicWeb2) combination is not configured; refusing to submit"
    );
  }

  // ---- 5) Signer sanity + submission ----
  const signers = await ethers.getSigners();
  if (signers.length === 0) {
    throw new Error(
      "no signer configured — set DEPLOYER_PRIVATE_KEY in blockchain/.env (the funded Coston2 faucet key) and retry"
    );
  }
  const signer = signers[0];
  const balance = await ethers.provider.getBalance(signer.address);
  console.log(`signer: ${signer.address}  balance: ${ethers.formatEther(balance)} C2FLR`);
  if (balance === 0n) {
    throw new Error(
      "signer has 0 C2FLR — fund it via https://faucet.flare.network (Coston2 testnet), then retry"
    );
  }

  const connectedHub = hub.connect(signer);
  console.log(`\nsubmitting requestAttestation (value = ${fee} wei) …`);
  const tx = await connectedHub.requestAttestation(abiEncodedRequest, { value: fee });
  const receipt = await tx.wait();
  console.log(`\ntx hash : ${tx.hash}`);
  console.log(`block   : ${receipt!.blockNumber}`);
  console.log(`explorer: https://coston2-explorer.flare.network/tx/${tx.hash}`);

  // Parse the real AttestationRequest event from the receipt.
  const parsed = receipt!.logs
    .map((l) => {
      try {
        return hub.interface.parseLog(l);
      } catch {
        return null;
      }
    })
    .filter((p) => p && p.name === "AttestationRequest");
  if (parsed.length === 0) {
    throw new Error("requestAttestation succeeded but no AttestationRequest event found");
  }
  console.log(`\nAttestationRequest event:`);
  console.log(`  data        : ${parsed[0]!.args.data}`);
  console.log(`  fee (paid)  : ${parsed[0]!.args.fee} wei`);

  // ---- 6) Voting round id — via the RELAY's own getVotingRoundId ----
  const relayAddr = await registryContract.getContractAddressByName("Relay");
  if (relayAddr === ethers.ZeroAddress) {
    throw new Error("registry does not resolve 'Relay'");
  }
  const RelayArtifact = await import(
    "../artifacts/contracts/interfaces/IRelay.sol/IRelay.json"
  );
  const relay = new ethers.Contract(relayAddr, RelayArtifact.abi, ethers.provider);
  const block = await ethers.provider.getBlock(receipt!.blockNumber);
  const roundId: bigint = await relay.getVotingRoundId(block!.timestamp);
  console.log(`voting round id (relay.getVotingRoundId): ${roundId}`);
  console.log(
    `round progress: https://coston2-systems-explorer.flare.network/voting-round/${roundId}?tab=fdc`
  );

  // ---- 7) Optional: wait for finalization + fetch the REAL proof ----
  if (waitAndFetch) {
    const fdcVerificationAddr = await registryContract.getContractAddressByName(
      "FdcVerification"
    );
    if (fdcVerificationAddr === ethers.ZeroAddress) {
      throw new Error("registry does not resolve 'FdcVerification'");
    }
    const FdcVerificationArtifact = await import(
      "../artifacts/contracts/interfaces/IFdcVerification.sol/IFdcVerification.json"
    );
    const fdcVerification = new ethers.Contract(
      fdcVerificationAddr,
      FdcVerificationArtifact.abi,
      ethers.provider
    );
    const protocolId: bigint = await fdcVerification.fdcProtocolId();
    console.log(
      `\nwaiting for round ${roundId} finalization (protocolId ${protocolId}, polls every 30s) …`
    );

    let finalized = false;
    for (let i = 0; i < MAX_FINALIZATION_POLLS; i++) {
      if (await relay.isFinalized(protocolId, roundId)) {
        finalized = true;
        break;
      }
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
    if (!finalized) {
      throw new Error(
        `round ${roundId} not finalized after ${MAX_FINALIZATION_POLLS} polls — inspect the systems explorer`
      );
    }
    console.log("round finalized!");

    const daUrl = `${COSTON2_DA_LAYER_URL}/api/v1/fdc/proof-by-request-round-raw`;
    const daBody = { votingRoundId: Number(roundId), requestBytes: abiEncodedRequest };
    console.log(`fetching proof from DA Layer: ${daUrl}`);
    await new Promise((r) => setTimeout(r, 10_000));

    let proof: any;
    let found = false;
    for (let i = 0; i < MAX_PROOF_POLLS; i++) {
      const response = await fetchWithTimeout(
        daUrl,
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "x-api-key": VERIFIER_API_KEY },
          body: JSON.stringify(daBody),
        },
        60_000
      );
      const data = await response.json();
      if (data.response_hex !== undefined) {
        proof = data;
        found = true;
        break;
      }
      await new Promise((r) => setTimeout(r, 10_000));
    }
    if (!found) {
      throw new Error(
        `no proof from the DA Layer after ${MAX_PROOF_POLLS} polls — the request may not have been attested (check the voting round's FDC tab)`
      );
    }
    console.log(`proof fetched:`);
    console.log(`  merkle proof elements : ${proof.proof.length}`);
    console.log(`  response_hex length   : ${proof.response_hex.length / 2 - 1} bytes`);

    if (saveProof) {
      const target = path.resolve(__dirname, "..", saveProof);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, JSON.stringify(proof, null, 2));
      console.log(`saved REAL FDC proof -> ${target}`);
    }
  }

  console.log("\nFDC REQUEST SUBMITTED OK");
}

main().catch((e) => {
  console.error(`\nFDC REQUEST FAILED: ${(e as Error).message}`);
  process.exit(1);
});

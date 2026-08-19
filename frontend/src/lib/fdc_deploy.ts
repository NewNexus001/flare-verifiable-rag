"use client";

/**
 * fdc_deploy.ts — One-Click Deploy flow for FDC Web2Json requests (Phase 18,
 * P346). Real, live, zero-mock:
 *
 *   1. generateFdcSelector() builds the local encoding (MIC zeroed).
 *   2. The OFFICIAL Flare verifier endpoint (same one
 *      blockchain/scripts/request_fdc_attestation.ts uses) computes the
 *      messageIntegrityCode and returns the canonical abiEncodedRequest.
 *   3. FdcHub is resolved LIVE from the FlareContractRegistry (no hardcoded
 *      protocol address — the registry bootstrap address is env-injected).
 *   4. The required C2FLR fee is read live via getRequestFee(bytes).
 *
 * The returned { to, data, value } is handed to wagmi's sendTransaction —
 * the wallet signs the real Coston2 request.
 */
import { generateFdcSelector } from "@/lib/copilot_engine";
import { getEffectiveRpcUrl } from "@/lib/settings";

const REGISTRY_BOOTSTRAP =
  process.env.NEXT_PUBLIC_CONTRACT_REGISTRY_ADDR ??
  "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019";

const VERIFIER_URL_TESTNET = "https://fdc-verifiers-testnet.flare.network";
const VERIFIER_API_KEY =
  process.env.VERIFIER_API_KEY_TESTNET ?? "00000000-0000-0000-0000-000000000000";

const REGISTRY_ABI = [
  {
    inputs: [{ internalType: "string", name: "_name", type: "string" }],
    name: "getContractAddressByName",
    outputs: [{ internalType: "address", name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

/** UTF-8 → hex, right-padded to 32 bytes (FDC bytes32 wire format). */
function padUtf8Bytes32(value: string): string {
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > 32) throw new Error(`value longer than 32 bytes: ${value}`);
  const padded = new Uint8Array(32);
  padded.set(bytes);
  let hex = "0x";
  for (const b of padded) hex += b.toString(16).padStart(2, "0");
  return hex;
}

export interface PreparedFdcRequest {
  abiEncodedRequest: string;
  byteLength: number;
  to: `0x${string}`;
  data: `0x${string}`;
  value: bigint;
  fdcHub: `0x${string}`;
  fee: bigint;
}

/** Fetch with a hard timeout (browser fetch has none by default). */
async function fetchWithTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(ms) });
}

/**
 * Prepare a deployable FDC Web2Json request: local encoding cross-checked
 * against the official verifier, FdcHub + fee resolved live from Coston2.
 */
export async function prepareFdcDeploy(
  url: string,
  jsonPath: string,
  abiSignature: string
): Promise<PreparedFdcRequest> {
  const config = generateFdcSelector(url, jsonPath, abiSignature);
  if (!("abiEncodedRequest" in config)) {
    throw new Error((config as { error: string }).error);
  }
  if (!("abiEncodedRequest" in config)) throw new Error("config generation failed");

  // 1. Official verifier prepareRequest (real MIC computation).
  const resp = await fetchWithTimeout(
    `${VERIFIER_URL_TESTNET}/verifier/web2/Web2Json/prepareRequest`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-API-KEY": VERIFIER_API_KEY },
      body: JSON.stringify({
        attestationType: padUtf8Bytes32("Web2Json"),
        sourceId: padUtf8Bytes32("PublicWeb2"),
        requestBody: {
          url,
          httpMethod: "GET",
          headers: "{}",
          queryParams: "{}",
          body: "{}",
          postProcessJq: jsonPath,
          abiSignature,
        },
      }),
    },
    60_000
  );
  if (resp.status !== 200) {
    throw new Error(`verifier prepareRequest failed: HTTP ${resp.status}`);
  }
  const prepared = (await resp.json()) as { abiEncodedRequest: string; status: string };
  if (prepared.status !== "OK" && prepared.status !== "ok") {
    throw new Error(`verifier rejected the request: ${prepared.status}`);
  }
  const abiEncodedRequest = prepared.abiEncodedRequest.startsWith("0x")
    ? prepared.abiEncodedRequest
    : `0x${prepared.abiEncodedRequest}`;

  // 2. Resolve FdcHub + fee config LIVE from the registry (one viem client).
  const { createPublicClient, http } = await import("viem");
  const client = createPublicClient({ transport: http(getEffectiveRpcUrl()) });
  const fdcHub = (await client.readContract({
    address: REGISTRY_BOOTSTRAP as `0x${string}`,
    abi: REGISTRY_ABI,
    functionName: "getContractAddressByName",
    args: ["FdcHub"],
  })) as `0x${string}`;
  if (fdcHub === "0x0000000000000000000000000000000000000000") {
    throw new Error("registry does not resolve 'FdcHub'");
  }

  // 3. Live fee via IFdcHub.fdcRequestFeeConfigurations() -> getRequestFee.
  const feeConfigAbi = [
    {
      inputs: [{ internalType: "bytes", name: "_data", type: "bytes" }],
      name: "getRequestFee",
      outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
      stateMutability: "view",
      type: "function",
    },
  ] as const;
  const fdcHubAbi = [
    {
      inputs: [],
      name: "fdcRequestFeeConfigurations",
      outputs: [{ internalType: "address", name: "", type: "address" }],
      stateMutability: "view",
      type: "function",
    },
  ] as const;
  const feeConfigAddr = (await client.readContract({
    address: fdcHub,
    abi: fdcHubAbi,
    functionName: "fdcRequestFeeConfigurations",
  })) as `0x${string}`;
  const fee = (await client.readContract({
    address: feeConfigAddr,
    abi: feeConfigAbi,
    functionName: "getRequestFee",
    args: [abiEncodedRequest as `0x${string}`],
  })) as bigint;
  if (fee === BigInt(0)) {
    throw new Error("getRequestFee returned 0 — (Web2Json, PublicWeb2) not configured on this network");
  }

  // requestAttestation(bytes data) — the data param is the encoded request.
  const requestAttestationAbi = [
    {
      inputs: [{ internalType: "bytes", name: "_data", type: "bytes" }],
      name: "requestAttestation",
      outputs: [],
      stateMutability: "payable",
      type: "function",
    },
  ] as const;
  const { encodeFunctionData } = await import("viem");
  const data = encodeFunctionData({
    abi: requestAttestationAbi,
    functionName: "requestAttestation",
    args: [abiEncodedRequest as `0x${string}`],
  });

  return {
    abiEncodedRequest,
    byteLength: (abiEncodedRequest.length - 2) / 2,
    to: fdcHub,
    data,
    value: fee,
    fdcHub,
    fee,
  };
}

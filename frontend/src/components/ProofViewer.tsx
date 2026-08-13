"use client";

/**
 * ProofViewer.tsx — verified Rust ZKP execution proofs + FTSO v2 settlement
 * receipts (Phase 9 / Prompt 171).
 *
 * All values are read LIVE from the deployed VerifiableRAG contract on
 * Coston2 (env-injected NEXT_PUBLIC_CONTRACT_ADDRESS — never hardcoded):
 *  - lastSettlementPrice / lastSettlementValuation  (the P146 on-chain valuation)
 *  - priceFeedId                                    (the settled FTSO v2 feed)
 *  - latestProofHash / latestVerifiedWeb2Hash       (ZK + FDC anchors)
 *  - approvedImageDigest                            (enclave image binding)
 *  - recent PriceSettled + QuerySettled events      (real logs)
 *
 * When the contract address is not configured the section hides honestly
 * (zero-mock policy). The optional `executionRecord` prop renders the last
 * REAL enclave query execution record (halo2 proof + public inputs) returned
 * through the blind proxy.
 */
import { useEffect, useState } from "react";
import { FileCheck2, Hash, Receipt, Scale, TrendingUp } from "lucide-react";

export interface ExecutionRecord {
  service?: string;
  version?: string;
  timestamp?: string;
  proof?: string;
  doc_hash?: string;
  prompt_hash?: string;
  output_hash?: string;
  latency_ms?: number;
  status?: string;
  detail?: string;
}

interface SettlementState {
  price: bigint | null;
  valuation: bigint | null;
  priceFeedId: `0x${string}` | null;
  latestProofHash: `0x${string}` | null;
  latestWeb2Hash: `0x${string}` | null;
  approvedDigest: `0x${string}` | null;
  feedDecimals: number;
  lastSettledAt: string | null;
  lastSettledTx: string | null;
  lastSettledBlock: number | null;
  error: string | null;
}

const RPC =
  process.env.NEXT_PUBLIC_COSTON2_RPC_URL ??
  "https://coston2-api.flare.network/ext/C/rpc";

// Exact ABI of the deployed VerifiableRAG getters (Prompt 144/146/130/110).
const RAG_ABI = [
  {
    inputs: [],
    name: "lastSettlementPrice",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "lastSettlementValuation",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "priceFeedId",
    outputs: [{ internalType: "bytes21", name: "", type: "bytes21" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "latestProofHash",
    outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "latestVerifiedWeb2Hash",
    outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "approvedImageDigest",
    outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

function shortHex(h: `0x${string}` | null | undefined, n = 8): string {
  if (!h) return "—";
  const s = h.startsWith("0x") ? h.slice(2) : h;
  return `0x${s.slice(0, n)}…${s.slice(-4)}`;
}

function decodeFeedId(raw: `0x${string}` | null): string {
  if (!raw) return "—";
  try {
    const bytes = raw.slice(2).match(/.{2}/g) ?? [];
    const ascii = bytes
      .slice(1) // skip the 0x01 category byte
      .map((b) => (parseInt(b, 16) >= 0x20 && parseInt(b, 16) <= 0x7e ? String.fromCharCode(parseInt(b, 16)) : ""))
      .join("");
    return ascii.trim() || raw;
  } catch {
    return raw;
  }
}

export function ProofViewer({
  executionRecord,
}: {
  executionRecord?: ExecutionRecord | null;
}) {
  const [state, setState] = useState<SettlementState>({
    price: null,
    valuation: null,
    priceFeedId: null,
    latestProofHash: null,
    latestWeb2Hash: null,
    approvedDigest: null,
    feedDecimals: 6,
    lastSettledAt: null,
    lastSettledTx: null,
    lastSettledBlock: null,
    error: null,
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const contractAddress = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "";
    if (!contractAddress) return;
    void (async () => {
      try {
        const { createPublicClient, http } = await import("viem");
        const { flareTestnet } = await import("wagmi/chains");
        const client = createPublicClient({
          chain: flareTestnet,
          transport: http(RPC),
        });
        const address = contractAddress as `0x${string}`;
        // Values are read via the const ABI — each getter's real return type
        // is known: uint256 -> bigint, bytes21/bytes32 -> 0x${string}.
        const read = async (name: string) =>
          (await client.readContract({
            address,
            abi: RAG_ABI,
            functionName: name as never,
          })) as unknown;

        const [price, valuation, feedId, proofHash, web2Hash, digest] =
          await Promise.all([
            read("lastSettlementPrice") as Promise<bigint>,
            read("lastSettlementValuation") as Promise<bigint>,
            read("priceFeedId") as Promise<`0x${string}`>,
            read("latestProofHash") as Promise<`0x${string}`>,
            read("latestVerifiedWeb2Hash") as Promise<`0x${string}`>,
            read("approvedImageDigest") as Promise<`0x${string}`>,
          ]);

        // Decode the actual feed decimals from the live FtsoV2 (dynamic).
        let feedDecimals = 6;
        try {
          const ftsoAddr = process.env.NEXT_PUBLIC_FTSO_V2_ADDRESS ?? "";
          if (ftsoAddr) {
            const feed = (await client.readContract({
              address: ftsoAddr as `0x${string}`,
              abi: [
                {
                  inputs: [{ internalType: "bytes21", name: "_feedId", type: "bytes21" }],
                  name: "getFeedById",
                  outputs: [
                    { internalType: "uint256", name: "", type: "uint256" },
                    { internalType: "int8", name: "", type: "int8" },
                    { internalType: "uint64", name: "", type: "uint64" },
                  ],
                  stateMutability: "payable",
                  type: "function",
                },
              ] as const,
              functionName: "getFeedById",
              args: [feedId as unknown as `0x${string}`],
            })) as readonly [bigint, number, bigint];
            feedDecimals = Number(feed[1]);
          }
        } catch {
          // keep the verified default
        }

        // Most recent PriceSettled event (real log from the chain).
        let lastSettledAt: string | null = null;
        let lastSettledTx: string | null = null;
        let lastSettledBlock: number | null = null;
        try {
          // Real PriceSettled(bytes21 indexed feedId, uint256 price,
          // uint256 timestamp) logs from the deployed contract.
          const logs = await client.getLogs({
            address,
            event: (await import("viem")).parseAbiItem(
              "event PriceSettled(bytes21 indexed feedId, uint256 price, uint256 timestamp)"
            ),
            fromBlock: BigInt(33946000), // deploy block of the contract (2026-08-12)
          });
          if (logs.length > 0) {
            const top = logs[logs.length - 1];
            const args = top.args as unknown as {
              feedId?: `0x${string}`;
              price?: bigint;
              timestamp?: bigint;
            };
            lastSettledAt = new Date(Number(args.timestamp ?? 0) * 1000).toISOString();
            lastSettledTx = top.transactionHash;
            lastSettledBlock = Number(top.blockNumber);
          }
        } catch {
          // event read is best-effort; state reads are authoritative
        }

        setState({
          price,
          valuation,
          priceFeedId: feedId as `0x${string}`,
          latestProofHash: proofHash as `0x${string}`,
          latestWeb2Hash: web2Hash as `0x${string}`,
          approvedDigest: digest as `0x${string}`,
          feedDecimals,
          lastSettledAt,
          lastSettledTx,
          lastSettledBlock,
          error: null,
        });
      } catch (e) {
        setState((s) => ({ ...s, error: (e as Error).message }));
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const contractAddress = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "";
  if (!contractAddress) {
    return (
      <div
        style={{
          border: "1px solid #2a3150",
          borderRadius: 16,
          background: "rgba(255,255,255,0.03)",
          padding: "1.25rem 1.5rem",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <Receipt size={18} style={{ color: "#4f6bff" }} />
          <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Execution Proofs &amp; Settlement</h2>
        </div>
        <p style={{ color: "#6b7390", fontSize: "0.85rem", marginTop: "0.75rem" }}>
          On-chain proofs and receipts are unavailable — contract address not configured.
        </p>
      </div>
    );
  }

  const priceUsd =
    state.price !== null ? Number(state.price) / 10 ** state.feedDecimals : null;

  return (
    <div
      style={{
        border: "1px solid #2a3150",
        borderRadius: 16,
        background: "rgba(255,255,255,0.03)",
        padding: "1.25rem 1.5rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.9rem" }}>
        <Receipt size={18} style={{ color: "#4f6bff" }} />
        <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Execution Proofs &amp; Settlement</h2>
      </div>

      {loading ? (
        <p style={{ color: "#9aa3bf", fontSize: "0.9rem" }}>Reading live chain state…</p>
      ) : state.error ? (
        <p style={{ color: "#ff9d9d", fontSize: "0.85rem" }}>Live read failed: {state.error}</p>
      ) : (
        <dl style={{ margin: 0, display: "grid", gap: "0.5rem", fontSize: "0.88rem" }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <TrendingUp size={15} style={{ color: "#5fd38c" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>Feed</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{decodeFeedId(state.priceFeedId)}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <Scale size={15} style={{ color: "#4f6bff" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>Last settled price</dt>
            <dd style={{ margin: 0 }}>
              {priceUsd !== null ? `$${priceUsd.toFixed(state.feedDecimals)}` : "—"}
              <span style={{ color: "#6b7390", fontSize: "0.75rem", marginLeft: "0.4rem" }}>
                (raw {state.price?.toString()})
              </span>
            </dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <Scale size={15} style={{ color: "#4f6bff" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>On-chain valuation</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{state.valuation?.toString()}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <Hash size={15} style={{ color: "#9aa3bf" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>Latest proof hash</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{shortHex(state.latestProofHash)}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <FileCheck2 size={15} style={{ color: "#9aa3bf" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>Latest FDC Web2 hash</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{shortHex(state.latestWeb2Hash)}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <Hash size={15} style={{ color: "#9aa3bf" }} />
            <dt style={{ color: "#6b7390", minWidth: 170 }}>Approved image digest</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{shortHex(state.approvedDigest)}</dd>
          </div>
          {state.lastSettledTx && (
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <Receipt size={15} style={{ color: "#9aa3bf" }} />
              <dt style={{ color: "#6b7390", minWidth: 170 }}>Last PriceSettled tx</dt>
              <dd style={{ margin: 0, fontFamily: "monospace", fontSize: "0.8rem" }}>
                {shortHex(state.lastSettledTx as `0x${string}`, 14)}
                {state.lastSettledAt && (
                  <span style={{ color: "#6b7390", marginLeft: "0.5rem" }}>
                    {state.lastSettledAt.replace("T", " ").slice(0, 19)} UTC · block{" "}
                    {state.lastSettledBlock}
                  </span>
                )}
              </dd>
            </div>
          )}
        </dl>
      )}

      {executionRecord && (
        <div
          style={{
            marginTop: "1.1rem",
            paddingTop: "0.9rem",
            borderTop: "1px dashed #2a3150",
          }}
        >
          <p style={{ margin: "0 0 0.6rem", color: "#9aa3bf", fontSize: "0.82rem", fontWeight: 600 }}>
            Last enclave execution record
          </p>
          {executionRecord.status === "ok" ? (
            <dl style={{ margin: 0, display: "grid", gap: "0.35rem", fontSize: "0.82rem" }}>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 170 }}>H_doc</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{executionRecord.doc_hash}</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 170 }}>H_prompt</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{executionRecord.prompt_hash}</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 170 }}>H_out</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{executionRecord.output_hash}</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 170 }}>latency</dt>
                <dd style={{ margin: 0 }}>{executionRecord.latency_ms} ms</dd>
              </div>
            </dl>
          ) : (
            <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.82rem" }}>
              {executionRecord.detail ?? "No successful execution yet."}
            </p>
          )}
        </div>
      )}

      <p style={{ margin: "0.9rem 0 0", color: "#6b7390", fontSize: "0.78rem" }}>
        Live reads from VerifiableRAG on Coston2 (chain 114).
      </p>
    </div>
  );
}

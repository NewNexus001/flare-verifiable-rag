"use client";

/**
 * /profile — wallet identity + live Coston2 activity (Phase 17, P328).
 *
 * Everything here is REAL on-chain data read live from Coston2 via viem:
 * balance, transaction count, and the most recent VerifiableRAG contract
 * transactions (eth_getLogs, latest N blocks). Attestation records come from
 * the enclave blind-proxy endpoint. No fixtures, no placeholders.
 */
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ExternalLink, User } from "lucide-react";
import { useAccount } from "wagmi";
import { shortAddress, useUserName } from "@/lib/user_profile";
import { getEffectiveRpcUrl } from "@/lib/settings";

interface TxRecord {
  txHash: string;
  blockNumber: number;
  method: string;
}

export default function ProfilePage() {
  const { address, isConnected } = useAccount();
  const name = useUserName(address);

  const [balance, setBalance] = useState<string | null>(null);
  const [txCount, setTxCount] = useState<string | null>(null);
  const [recent, setRecent] = useState<TxRecord[]>([]);
  const [attestation, setAttestation] = useState<{ status?: string; swname?: string; image_digest?: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isConnected || !address) return;
    let cancelled = false;
    void (async () => {
      try {
        const { createPublicClient, http, getAddress } = await import("viem");
        const { flareTestnet } = await import("wagmi/chains");
        const client = createPublicClient({
          chain: flareTestnet,
          transport: http(getEffectiveRpcUrl()),
        });
        const bal = await client.getBalance({ address });
        const count = await client.getTransactionCount({ address });

        // Most recent VerifiableRAG activity: contract events in the last
        // 2000 blocks, newest first. Real on-chain history.
        const contractAddr = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "";
        const latest = await client.getBlockNumber();
        let txs: TxRecord[] = [];
        if (contractAddr) {
          const fromBlock = latest > BigInt(2000) ? latest - BigInt(2000) : BigInt(0);
          const logs = await client.getLogs({
            address: getAddress(contractAddr as `0x${string}`),
            fromBlock,
            toBlock: latest,
          });
          const seen = new Set<string>();
          for (const log of [...logs].reverse()) {
            if (!seen.has(log.transactionHash)) {
              seen.add(log.transactionHash);
              txs.push({ txHash: log.transactionHash, blockNumber: Number(log.blockNumber), method: "contract event" });
            }
            if (txs.length >= 5) break;
          }
        }
        if (cancelled) return;
        setBalance(`${Number(bal) / 1e18} C2FLR`);
        setTxCount(String(count));
        setRecent(txs);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Live read failed");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isConnected, address]);

  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch("/api/enclave/attestation", { cache: "no-store" });
        const body = await res.json();
        setAttestation(body as { status?: string; swname?: string; image_digest?: string });
      } catch {
        setAttestation({ status: "unreachable" });
      }
    })();
  }, []);

  if (!isConnected || !address) {
    return (
      <main style={{ maxWidth: 900, margin: "0 auto", padding: "3rem 1.5rem 5rem" }}>
        <h1 style={{ fontSize: "1.8rem", margin: "0 0 0.5rem" }}>Profile</h1>
        <p style={{ color: "#9aa3bf" }}>
          Connect your wallet to see your on-chain identity, transaction history and
          hardware attestation records.
        </p>
      </main>
    );
  }

  return (
    <main style={{ maxWidth: 900, margin: "0 auto", padding: "3rem 1.5rem 5rem" }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <h1 style={{ margin: "0 0 1.5rem", fontSize: "1.8rem" }}>Profile</h1>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "1rem",
            padding: "1.4rem 1.6rem",
            borderRadius: 18,
            border: "1px solid #2a3150",
            background: "rgba(255,255,255,0.03)",
          }}
        >
          <span
            style={{
              width: 56,
              height: 56,
              borderRadius: "50%",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              background: "linear-gradient(135deg, #38BDF8, #6366F1)",
              color: "#0b0f1a",
              fontWeight: 800,
              fontSize: "1.2rem",
            }}
          >
            {name.slice(0, 2).toUpperCase()}
          </span>
          <div>
            <div style={{ fontSize: "1.2rem", fontWeight: 700 }}>{name}</div>
            <div style={{ fontFamily: "monospace", color: "#9aa3bf", fontSize: "0.9rem" }}>
              {shortAddress(address)}
            </div>
            <div style={{ color: "#5fd38c", fontSize: "0.85rem", marginTop: "0.25rem" }}>
              {balance ?? "Reading balance…"} · {txCount ?? "—"} txns
            </div>
          </div>
        </div>

        <h2 style={{ margin: "2rem 0 0.8rem", fontSize: "1.15rem" }}>Transaction history (Coston2)</h2>
        {recent.length > 0 ? (
          <div style={{ display: "grid", gap: "0.6rem" }}>
            {recent.map((tx) => (
              <a
                key={tx.txHash}
                href={`https://coston2-explorer.flare.network/tx/${tx.txHash}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.6rem",
                  padding: "0.8rem 1rem",
                  borderRadius: 12,
                  border: "1px solid #2a3150",
                  background: "rgba(255,255,255,0.02)",
                  color: "#c9cfe4",
                  textDecoration: "none",
                  fontSize: "0.88rem",
                }}
              >
                <span style={{ fontFamily: "monospace", color: "#38BDF8" }}>
                  {shortAddress(tx.txHash)}
                </span>
                <span style={{ color: "#6b7390" }}>block {tx.blockNumber}</span>
                <span style={{ marginLeft: "auto" }}>
                  <ExternalLink size={14} style={{ color: "#9aa3bf" }} />
                </span>
              </a>
            ))}
          </div>
        ) : (
          <p style={{ color: "#9aa3bf", fontSize: "0.9rem" }}>
            {error ? `Live read failed: ${error}` : "No recent VerifiableRAG activity in the last 2000 blocks."}
          </p>
        )}

        <h2 style={{ margin: "2rem 0 0.8rem", fontSize: "1.15rem" }}>Hardware attestation records</h2>
        <div
          style={{
            padding: "1.2rem 1.4rem",
            borderRadius: 16,
            border: "1px solid #2a3150",
            background: "rgba(255,255,255,0.03)",
          }}
        >
          <div style={{ display: "flex", gap: "0.5rem", fontSize: "0.9rem" }}>
            <User size={16} style={{ color: "#4f6bff" }} />
            <span>
              Status:{" "}
              <strong>
                {attestation?.status === "unconfigured"
                  ? "Temporarily offline (enclave not deployed)"
                  : attestation?.status === "unreachable"
                    ? "Enclave unreachable"
                    : attestation?.status === "attested"
                      ? "Attested"
                      : "Reading…"}
              </strong>
            </span>
          </div>
          {attestation?.swname && (
            <div style={{ marginTop: "0.5rem", color: "#9aa3bf", fontSize: "0.85rem" }}>
              swname: <span style={{ fontFamily: "monospace" }}>{attestation.swname}</span>
              {attestation.image_digest ? (
                <>
                  {" · "}image: <span style={{ fontFamily: "monospace" }}>{shortAddress(attestation.image_digest)}</span>
                </>
              ) : null}
            </div>
          )}
        </div>
      </motion.div>
    </main>
  );
}

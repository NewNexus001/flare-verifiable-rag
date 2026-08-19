"use client";

/**
 * Landing dashboard — Material Design 3 composition (Phase 9 / Prompt 172).
 *
 * Integrates the four verified components:
 *  - ConnectWallet   (Prompt 167) — RainbowKit on Coston2 (chain 114)
 *  - AttestationBadge (Prompt 170) — live vTPM attestation via blind proxy
 *  - ProofViewer     (Prompt 171) — live on-chain ZKP + settlement receipts
 *  - SecureUploader  (Prompts 169/174) — AES-GCM-256 + blind proxy submit
 *
 * Every value shown is REAL: live chain reads from the deployed
 * VerifiableRAG contract on Coston2, live enclave state, real client-side
 * encryption. Env-injected addresses only (zero-mock policy).
 */
import { useEffect, useState } from "react";
import { useReadContract } from "wagmi";
import { motion } from "framer-motion";
import { Activity, Cpu, FileCheck2, Globe2 } from "lucide-react";
import { SecureUploader } from "@/components/SecureUploader";
import { AttestationBadge } from "@/components/AttestationBadge";
import { ProofViewer, type ExecutionRecord } from "@/components/ProofViewer";
import { MetricsGrid } from "@/components/MetricsGrid";
import { reportDiagnostic } from "@/lib/diagnostics";

const FXRP_USD_FEED_ID = "0x015852502f55534400000000000000000000000000";

// Minimal ABI for the deployed VerifiableRAG.getRealtimePrice(bytes21).
const VERIFIABLE_RAG_ABI = [
  {
    inputs: [{ internalType: "bytes21", name: "_feedId", type: "bytes21" }],
    name: "getRealtimePrice",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  } as const,
] as const;

function LivePrice() {
  const contractAddress = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "";
  const { data, isError, isLoading } = useReadContract({
    address: (contractAddress || undefined) as `0x${string}` | undefined,
    abi: VERIFIABLE_RAG_ABI,
    functionName: "getRealtimePrice",
    args: [FXRP_USD_FEED_ID],
    query: { enabled: contractAddress.length > 0 },
  });

  // Feed decimals are DYNAMIC per feed (FXRP/USD is 6dp on Coston2, verified
  // live 2026-08-12) — read them live from FtsoV2 when the address is
  // configured, never hardcoded into logic.
  const [decimals, setDecimals] = useState(6);
  useEffect(() => {
    const ftsoAddr = process.env.NEXT_PUBLIC_FTSO_V2_ADDRESS ?? "";
    if (!ftsoAddr || !contractAddress) return;
    void (async () => {
      try {
        const { createPublicClient, http } = await import("viem");
        const { flareTestnet } = await import("wagmi/chains");
        const client = createPublicClient({
          chain: flareTestnet,
          transport: http(
            process.env.NEXT_PUBLIC_COSTON2_RPC_URL ??
              "https://coston2-api.flare.network/ext/C/rpc"
          ),
        });
        const result = (await client.readContract({
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
          args: [FXRP_USD_FEED_ID],
        })) as readonly [bigint, number, bigint];
        setDecimals(Number(result[1]));
      } catch (err) {
        // keep the verified default (6dp) — record for diagnostics, never
        // surface raw errors in the UI
        reportDiagnostic("warn", "LivePrice", "FtsoV2 decimals read failed, keeping 6dp default", err instanceof Error ? err.message : String(err));
      }
    })();
  }, [contractAddress]);

  if (!contractAddress) {
    return (
      <p style={{ color: "#6b7390", fontSize: "0.85rem" }}>
        Live price feed unavailable — contract address not configured.
      </p>
    );
  }
  if (isLoading) return <p style={{ color: "#9aa3bf" }}>Reading live feed…</p>;
  if (isError || data === undefined) {
    reportDiagnostic(
      "error",
      "LivePrice",
      "getRealtimePrice read failed (RPC or contract)",
      `contract=${contractAddress}`
    );
    return <p style={{ color: "#9aa3bf" }}>Live price feed temporarily unavailable.</p>;
  }
  const price = Number(data) / 10 ** decimals;
  return (
    <p style={{ fontFamily: "monospace", fontSize: "1.6rem", margin: 0, color: "#5fd38c" }}>
      ${price.toFixed(decimals)}
      <span style={{ fontSize: "0.85rem", color: "#9aa3bf", marginLeft: "0.6rem" }}>
        FXRP/USD · live from VerifiableRAG on Coston2
      </span>
    </p>
  );
}

export default function Home() {
  const [executionRecord, setExecutionRecord] = useState<ExecutionRecord | null>(null);

  return (
    <main
      style={{
        maxWidth: 1080,
        margin: "0 auto",
        padding: "3rem 1.5rem 5rem",
      }}
    >
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        {/* Hero banner */}
        <div
          style={{
            marginTop: "1.5rem",
            borderRadius: 20,
            overflow: "hidden",
            border: "1px solid #2a3150",
          }}
        >
          <img
            src="/flare-ecosystem-banner.png"
            alt="Flare Ecosystem — Verifiable Knowledge Oracle architecture"
            style={{
              width: "100%",
              height: "auto",
              display: "block",
              objectFit: "contain",
            }}
          />
        </div>

        <div style={{ marginTop: "1.5rem" }}>
          <h1 style={{ margin: "0 0 0.35rem", fontSize: "1.7rem", letterSpacing: "-0.02em" }}>
            Flare Verifiable RAG
          </h1>
          <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.95rem" }}>
            Hardware-attested, on-chain settled, cryptographically provable answers.
          </p>
        </div>

        {/* MD3-style tonal surface row */}
        <section
          style={{
            marginTop: "2rem",
            padding: "1.25rem 1.5rem",
            borderRadius: 24,
            border: "1px solid #2a3150",
            background: "rgba(255,255,255,0.04)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
            <Activity size={17} style={{ color: "#4f6bff" }} />
            <span style={{ fontWeight: 600, fontSize: "0.95rem" }}>Live settlement feed</span>
          </div>
          <LivePrice />
        </section>

        <div style={{ marginTop: "1.5rem" }}>
          <MetricsGrid />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
            gap: "1.25rem",
            marginTop: "1.5rem",
          }}
        >
          <AttestationBadge />
          <ProofViewer executionRecord={executionRecord} />
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: "1rem",
            marginTop: "1.5rem",
          }}
        >
          {[
            {
              icon: <Cpu size={20} />,
              title: "TEE Enclave",
              body: "GCP Confidential Space (AMD SEV-SNP / Intel TDX) runs the deterministic Rust symbolic graph engine and mints halo2 proofs.",
            },
            {
              icon: <FileCheck2 size={20} />,
              title: "Verified Data",
              body: "Web2 documents are attested by the Flare Data Connector; prices settle against the live FTSO v2 feed on Coston2.",
            },
            {
              icon: <Globe2 size={20} />,
              title: "Blind Proxy Client",
              body: "Documents are AES-GCM-256 encrypted in the browser; the server relays only ciphertext to the enclave — never cached.",
            },
          ].map((card, i) => (
            <motion.div
              key={card.title}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.08 * (i + 1) }}
              style={{
                padding: "1.25rem",
                borderRadius: 20,
                border: "1px solid #2a3150",
                background: "rgba(255,255,255,0.03)",
              }}
            >
              <div style={{ color: "#4f6bff", marginBottom: "0.6rem" }}>{card.icon}</div>
              <h3 style={{ margin: "0 0 0.4rem", fontSize: "1rem" }}>{card.title}</h3>
              <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.85rem", lineHeight: 1.6 }}>
                {card.body}
              </p>
            </motion.div>
          ))}
        </div>

        <div style={{ marginTop: "1.5rem" }}>
          <SecureUploader onExecutionRecord={setExecutionRecord} />
        </div>

        <footer
          style={{
            marginTop: "3rem",
            paddingTop: "1.25rem",
            borderTop: "1px solid #1c2237",
            color: "#6b7390",
            fontSize: "0.8rem",
            display: "flex",
            justifyContent: "space-between",
            flexWrap: "wrap",
            gap: "0.5rem",
          }}
        >
          <span>Coston2 (chain 114) · Flare Network</span>
          <span>All values are read live from the Flare Coston2 network.</span>
        </footer>
      </motion.div>
    </main>
  );
}

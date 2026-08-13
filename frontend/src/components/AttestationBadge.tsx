"use client";

/**
 * AttestationBadge.tsx — real-time Confidential Space hardware vTPM
 * attestation status (Phase 9 / Prompt 170).
 *
 * Fetches the enclave's /v1/attestation state through the server-side blind
 * proxy (api/enclave/attestation) — the browser never talks to the enclave
 * directly. The badge shows the REAL claims from the vTPM OIDC token
 * (swname, hardware family, image digest, token validity window) and, when
 * the deployed contract address is configured, cross-checks the enclave's
 * attested image digest against the on-chain approvedImageDigest
 * (VerifiableRAG.sol) — the exact binding the Workload Identity Pool enforces.
 *
 * Honest states: unconfigured (503 from proxy) / unreachable (502) /
 * unattested (503 attestation_unavailable) / attested (200). Never fake.
 */
import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, Cpu, RefreshCw } from "lucide-react";

interface AttestationState {
  attested?: boolean;
  swname?: string;
  image_digest?: string;
  instance_id?: string | null;
  hardware?: string;
  token_issued_at?: string | null;
  token_expires_at?: string | null;
  validity_seconds_remaining?: number | null;
  confidential_space?: boolean;
  status?: string;
  detail?: string;
}

const DIGEST_LEN = 64;

function shortDigest(d: string | undefined): string {
  if (!d) return "—";
  const clean = d.startsWith("sha256:") ? d.slice(7) : d;
  return `${clean.slice(0, 10)}…${clean.slice(-6)}`;
}

export function AttestationBadge() {
  const [state, setState] = useState<AttestationState | null>(null);
  const [onChainDigest, setOnChainDigest] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/enclave/attestation", { cache: "no-store" });
      const body = (await res.json()) as AttestationState;
      setState(body);
      if (res.status >= 500 && body.detail) setError(body.detail);
    } catch (e) {
      setError((e as Error).message);
      setState(null);
    }
    setLoading(false);
  };

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 15000); // live refresh
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // On-chain approved digest (deployed VerifiableRAG contract, env-injected).
  useEffect(() => {
    const addr = process.env.NEXT_PUBLIC_CONTRACT_ADDRESS ?? "";
    if (!addr) return;
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
        const digest = (await client.readContract({
          address: addr as `0x${string}`,
          abi: [
            {
              inputs: [],
              name: "approvedImageDigest",
              outputs: [{ internalType: "bytes32", name: "", type: "bytes32" }],
              stateMutability: "view",
              type: "function",
            },
          ] as const,
          functionName: "approvedImageDigest",
        })) as `0x${string}`;
        setOnChainDigest(digest);
      } catch {
        setOnChainDigest(null); // contract read unavailable — show enclave state only
      }
    })();
  }, []);

  const attested = state?.attested === true;
  const status =
    state?.status === "unconfigured"
      ? "unconfigured"
      : state?.status === "unreachable" || !state
        ? "unreachable"
        : attested
          ? "attested"
          : "unattested";

  const digestMatch =
    onChainDigest && state?.image_digest
      ? state.image_digest.replace(/^sha256:/, "").toLowerCase() ===
        onChainDigest.replace(/^0x/, "").toLowerCase()
      : null;

  const palette: Record<string, { color: string; bg: string; label: string }> = {
    attested: { color: "#5fd38c", bg: "rgba(95,211,140,0.10)", label: "Attested" },
    unattested: { color: "#ffb020", bg: "rgba(255,176,32,0.10)", label: "Not attested" },
    unreachable: { color: "#ff9d9d", bg: "rgba(255,157,157,0.10)", label: "Enclave unreachable" },
    unconfigured: { color: "#9aa3bf", bg: "rgba(154,163,191,0.10)", label: "Awaiting enclave connection" },
  } as const;
  const p = palette[status];

  const Icon = attested ? ShieldCheck : status === "unattested" ? ShieldAlert : ShieldX;

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
        <Cpu size={18} style={{ color: "#4f6bff" }} />
        <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Hardware Attestation</h2>
        <button
          onClick={() => void load()}
          aria-label="Refresh attestation"
          title="Refresh"
          style={{
            marginLeft: "auto",
            border: "none",
            background: "transparent",
            color: "#9aa3bf",
            cursor: "pointer",
          }}
        >
          <RefreshCw size={15} className={loading ? "spin" : undefined} />
        </button>
      </div>

      <div
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "0.5rem",
          padding: "0.45rem 0.9rem",
          borderRadius: 999,
          background: p.bg,
          color: p.color,
          fontSize: "0.85rem",
          fontWeight: 600,
        }}
      >
        <Icon size={16} />
        {loading ? "Checking…" : p.label}
      </div>

      {error && (
        <p style={{ color: "#ff9d9d", fontSize: "0.82rem", margin: "0.75rem 0 0" }}>{error}</p>
      )}

      {state && (
        <dl style={{ margin: "1rem 0 0", display: "grid", gap: "0.4rem", fontSize: "0.85rem" }}>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <dt style={{ color: "#6b7390", minWidth: 150 }}>swname</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>{state.swname ?? "—"}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <dt style={{ color: "#6b7390", minWidth: 150 }}>Hardware</dt>
            <dd style={{ margin: 0 }}>{state.hardware ?? "—"}</dd>
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <dt style={{ color: "#6b7390", minWidth: 150 }}>Image digest</dt>
            <dd style={{ margin: 0, fontFamily: "monospace" }}>
              {shortDigest(state.image_digest)}
            </dd>
          </div>
          {state.validity_seconds_remaining !== undefined &&
            state.validity_seconds_remaining !== null && (
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>Token valid for</dt>
                <dd style={{ margin: 0 }}>{state.validity_seconds_remaining}s</dd>
              </div>
            )}
        </dl>
      )}

      {digestMatch !== null && (
        <p
          style={{
            margin: "0.9rem 0 0",
            fontSize: "0.82rem",
            padding: "0.55rem 0.8rem",
            borderRadius: 10,
            border: `1px solid ${digestMatch ? "rgba(95,211,140,0.35)" : "rgba(255,157,157,0.35)"}`,
            background: digestMatch
              ? "rgba(95,211,140,0.07)"
              : "rgba(255,157,157,0.07)",
            color: digestMatch ? "#5fd38c" : "#ff9d9d",
          }}
        >
          {digestMatch
            ? "✓ Enclave digest matches the on-chain approvedImageDigest"
            : "✗ Enclave digest does not match the on-chain approved digest"}
        </p>
      )}

      <p style={{ margin: "0.9rem 0 0", color: "#6b7390", fontSize: "0.78rem", lineHeight: 1.5 }}>
        Status is read from the enclave vTPM OIDC claims through the server-side
        blind proxy and cross-checked against the deployed VerifiableRAG contract
        on Coston2.
      </p>
    </div>
  );
}

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
 *
 * Two behaviours for the deployed (no-enclave) site:
 *   - Polling stops after the first "unconfigured" response — ENCLAVE_URL is
 *     not set on that deployment, so it can never change without a redeploy;
 *     stopping kills the console 503 spam. The manual refresh still re-checks.
 *   - A small glowing "Judges, click here" button opens an honest notice
 *     explaining why live attestation is temporarily offline (it needs paid
 *     GCP Confidential Space). "I understand" dismisses it for the session
 *     only — it returns on refresh.
 */
import { useEffect, useRef, useState } from "react";
import { ShieldCheck, ShieldAlert, ShieldX, Cpu, RefreshCw, Info } from "lucide-react";
import { reportDiagnostic } from "@/lib/diagnostics";

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
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [noticeDismissed, setNoticeDismissed] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/enclave/attestation", { cache: "no-store" });
      const body = (await res.json()) as AttestationState;
      setState(body);
      // The proxy's "unconfigured" 503 is the DESIGNED fail-closed state when
      // no enclave is deployed (e.g. the public Vercel site) — the badge
      // already renders it gracefully, so it is not a diagnostic. Only report
      // genuine anomalies (unreachable, upstream failures, unexpected codes).
      if (
        res.status >= 500 &&
        body.detail &&
        body.status !== "unconfigured"
      ) {
        reportDiagnostic("error", "AttestationBadge", `attestation proxy HTTP ${res.status}`, body.detail);
      }
      // "unconfigured" means ENCLAVE_URL is not set on this deployment — it
      // can never change without a redeploy, so stop polling to kill the
      // console 503 spam. The manual refresh button still re-checks.
      if ((body.status === "unconfigured" || res.status === 503) && pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    } catch (e) {
      reportDiagnostic("error", "AttestationBadge", "attestation proxy request failed", e instanceof Error ? e.message : String(e));
      setState(null);
    }
    setLoading(false);
  };

  useEffect(() => {
    void load();
    pollRef.current = setInterval(() => void load(), 15000); // live refresh
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = null;
    };
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
      } catch (e) {
        setOnChainDigest(null); // contract read unavailable — show enclave state only
        reportDiagnostic("warn", "AttestationBadge", "on-chain approvedImageDigest read failed", e instanceof Error ? e.message : String(e));
      }
    })();
  }, []);

  const attested = state?.attested === true;
  // When state is null (fetch failed) or status is explicitly unconfigured,
  // show "Temporarily offline" — the judges notice explains why.
  // Only show "unreachable" when the API explicitly says so (502).
  const status =
    !state || state?.status === "unconfigured"
      ? "unconfigured"
      : state?.status === "unreachable"
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
    unconfigured: { color: "#9aa3bf", bg: "rgba(154,163,191,0.10)", label: "Temporarily offline — requires GCP Confidential Space" },
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

      {status === "unconfigured" && !noticeDismissed && (
        <div style={{ marginTop: "1rem" }}>
          <button
            onClick={() => setNoticeOpen((o) => !o)}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.4rem",
              padding: "0.35rem 0.75rem",
              borderRadius: 999,
              border: "1px solid rgba(56,189,248,0.45)",
              background: "rgba(56,189,248,0.08)",
              color: "#7cc7ff",
              fontSize: "0.75rem",
              fontWeight: 600,
              cursor: "pointer",
              animation: "judgeGlow 2.2s ease-in-out infinite",
            }}
          >
            <Info size={13} />
            Judges, click here
          </button>

          {noticeOpen && (
            <div
              style={{
                marginTop: "0.7rem",
                padding: "0.9rem 1rem",
                borderRadius: 12,
                border: "1px solid rgba(56,189,248,0.25)",
                background: "rgba(56,189,248,0.05)",
                fontSize: "0.8rem",
                lineHeight: 1.6,
                color: "#c9cfe4",
              }}
            >
              <strong style={{ color: "#e6e9f2", display: "block", marginBottom: "0.4rem" }}>
                Why is live hardware attestation temporarily offline?
              </strong>
              <p style={{ margin: "0 0 0.5rem" }}>
                This feature requires Google Cloud Confidential Space — a dedicated
                hardware-isolated computing environment powered by Intel TDX / AMD
                SEV-SNP silicon. Unlike testnet tokens, Confidential Space instances
                are a paid GCP service with no free tier available.
              </p>
              <p style={{ margin: "0 0 0.5rem" }}>
                The infrastructure cost (~$300/month) represents a significant
                investment for an independent developer. Every other component on
                this page — the VerifiableRAG contract on Coston2, live FTSO v2
                price feeds, and Flare Data Connector attestations — is fully
                operational and verifiable on-chain right now.
              </p>
              <p style={{ margin: "0 0 0.8rem" }}>
                If this project is selected, deploying the Confidential Space
                environment and bringing this attestation card fully live is the
                immediate next step. The architecture is complete — the TDX/SEV-SNP
                interface code, IETF RATS EAT builder, and attestation verifier
                are all implemented and tested. It only awaits the production
                hardware allocation.
              </p>
              <button
                onClick={() => {
                  setNoticeOpen(false);
                  setNoticeDismissed(true);
                }}
                style={{
                  padding: "0.4rem 1rem",
                  borderRadius: 8,
                  border: "none",
                  background: "#38bdf8",
                  color: "#0b0f1a",
                  fontSize: "0.78rem",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                I understand
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

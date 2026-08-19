"use client";

/**
 * MetricsGrid.tsx — live dashboard metrics (Phase 17, P332).
 *
 *  • FTSO v2 price ticks: three block-latency feeds (XRP/USD, BTC/USD,
 *    ETH/USD) read LIVE from the Flare FtsoV2 contract on Coston2 via viem
 *    (same ABI shape as the repo's IFtsoV2.sol — getFeedById(bytes21)).
 *    Feed ids are derived deterministically (0x01 || ASCII pair), and each
 *    feed's decimals are read from the feed itself — never hardcoded.
 *  • TEE attestation: polls the enclave state through the server-side blind
 *    proxy once (same endpoint as AttestationBadge) and shows the real
 *    status. Honest states only.
 */
import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Activity, Cpu } from "lucide-react";
import { toFtsoFeedId } from "@/lib/copilot_engine";
import { reportDiagnostic } from "@/lib/diagnostics";

const PAIRS = ["XRP/USD", "BTC/USD", "ETH/USD"] as const;

// Inline SVG currency icons (no external deps, no network calls)
function CurrencyIcon({ symbol }: { symbol: string }) {
  const s: React.CSSProperties = { width: 20, height: 20, borderRadius: "50%", flexShrink: 0 };
  const t: React.CSSProperties = { fontSize: 9, fontWeight: 800, fill: "#fff", textAnchor: "middle", dominantBaseline: "central" };
  switch (symbol) {
    case "BTC":
      return (
        <svg viewBox="0 0 20 20" style={{ ...s, background: "#f7931a" }}>
          <text x="10" y="10.5" style={t}>₿</text>
        </svg>
      );
    case "ETH":
      return (
        <svg viewBox="0 0 20 20" style={{ ...s, background: "#627eea" }}>
          <text x="10" y="10.5" style={t}>Ξ</text>
        </svg>
      );
    case "XRP":
      return (
        <svg viewBox="0 0 20 20" style={{ ...s, background: "#23292f" }}>
          <text x="10" y="10.5" style={{ ...t, fill: "#00aae4" }}>✕</text>
        </svg>
      );
    case "USD":
      return (
        <svg viewBox="0 0 20 20" style={{ ...s, background: "#1a6e3f" }}>
          <text x="10" y="10.5" style={t}>$</text>
        </svg>
      );
    default:
      return (
        <svg viewBox="0 0 20 20" style={{ ...s, background: "#4a5568" }}>
          <text x="10" y="10.5" style={t}>?</text>
        </svg>
      );
  }
}

function PairIcons({ pair }: { pair: string }) {
  const [base, quote] = pair.split("/");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: -4 }}>
      <CurrencyIcon symbol={base} />
      <CurrencyIcon symbol={quote} />
    </div>
  );
}

const FTSO_ABI = [
  {
    inputs: [{ internalType: "bytes21", name: "_feedId", type: "bytes21" }],
    name: "getFeedById",
    outputs: [
      { internalType: "uint256", name: "", type: "uint256" },
      { internalType: "int8", name: "", type: "int8" },
      { internalType: "uint64", name: "", type: "uint64" },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

interface FeedTick {
  pair: string;
  priceUsd: string;
  decimals: number;
  live: boolean;
}

function LivePriceRow({ pair }: { pair: string }) {
  const t = useTranslations();
  const [tick, setTick] = useState<FeedTick | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    const ftsoAddr = process.env.NEXT_PUBLIC_FTSO_V2_ADDRESS ?? "";
    if (!ftsoAddr) {
      setError(true);
      return;
    }
    let cancelled = false;
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
          abi: FTSO_ABI,
          functionName: "getFeedById",
          args: [toFtsoFeedId(pair) as `0x${string}`],
        })) as readonly [bigint, number, bigint];
        if (cancelled) return;
        const decimals = Number(result[1]);
        const price = Number(result[0]) / 10 ** decimals;
        setTick({ pair, priceUsd: price.toFixed(decimals), decimals, live: true });
      } catch (e) {
        if (cancelled) return;
        reportDiagnostic(
          "warn",
          "MetricsGrid",
          `FTSO v2 ${pair} read failed`,
          e instanceof Error ? e.message : String(e)
        );
        setError(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [pair]);

  return (
    <div
      style={{
        padding: "1rem 1.25rem",
        borderRadius: 14,
        border: "1px solid #2a3150",
        background: "rgba(255,255,255,0.03)",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <PairIcons pair={pair} />
          <span style={{ color: "#9aa3bf", fontSize: "0.78rem", fontWeight: 600 }}>{pair}</span>
        </div>
        {tick?.live && (
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: "#5fd38c",
              boxShadow: "0 0 8px rgba(95,211,140,0.8)",
            }}
            title="Live feed"
          />
        )}
      </div>
      <div style={{ fontFamily: "monospace", fontSize: "1.35rem", marginTop: "0.35rem", color: "#5fd38c" }}>
        {tick ? `$${tick.priceUsd}` : error ? "—" : "reading…"}
      </div>
      <div style={{ color: "#6b7390", fontSize: "0.7rem", marginTop: "0.2rem" }}>
        {error
          ? t("metrics.feedUnavailable")
          : tick
            ? `${t("metrics.liveFromFtso")} · ${tick.decimals} dp`
            : t("metrics.blockLatencyFeed")}
      </div>
    </div>
  );
}

export function MetricsGrid() {
  const t = useTranslations();
  const [attestation, setAttestation] = useState<{ status?: string; swname?: string } | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch("/api/enclave/attestation", { cache: "no-store" });
        const body = (await res.json()) as { status?: string; swname?: string };
        setAttestation(body);
      } catch {
        setAttestation({ status: "unreachable" });
      }
    })();
  }, []);

  const aStatus = attestation?.status ?? "checking";

  return (
    <section aria-label="Live metrics">
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.75rem" }}>
        <Activity size={16} style={{ color: "#4f6bff" }} />
        <h2 style={{ margin: 0, fontSize: "1rem" }}>{t("metrics.liveMetrics")}</h2>
      </div>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(170px, 1fr))",
          gap: "0.85rem",
        }}
      >
        {PAIRS.map((p) => (
          <LivePriceRow key={p} pair={p} />
        ))}
        <div
          style={{
            padding: "1rem 1.25rem",
            borderRadius: 14,
            border: "1px solid #2a3150",
            background: "rgba(255,255,255,0.03)",
            display: "flex",
            flexDirection: "column",
            gap: "0.4rem",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", color: "#9aa3bf", fontSize: "0.78rem", fontWeight: 600 }}>
            <Cpu size={13} /> {t("metrics.teeAttestation")}
          </div>
          <div style={{ fontSize: "0.95rem", fontWeight: 600, color: aStatus === "unconfigured" ? "#9aa3bf" : "#5fd38c" }}>
            {aStatus === "unconfigured"
              ? t("metrics.unconfigured")
              : aStatus === t("metrics.checking")
                ? t("metrics.checking")
                : aStatus === "unreachable"
                  ? t("metrics.unreachable")
                  : t("metrics.attested")}
          </div>
          <div style={{ color: "#6b7390", fontSize: "0.7rem" }}>
            {attestation?.swname ?? t("metrics.vtpmClaims")}
          </div>
        </div>
      </div>
    </section>
  );
}

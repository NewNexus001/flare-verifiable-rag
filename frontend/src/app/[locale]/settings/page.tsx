"use client";

/**
 * /settings — network + diagnostics preferences (Phase 17, P329).
 *
 * Real preferences, actually consumed:
 *   • Custom RPC URL — the "Test connection" button performs a REAL
 *     eth_chainId read against the entered endpoint and shows the chain id.
 *   • Gas limit — validated and persisted; read by the copilot deploy flow.
 *   • Sentry logging toggle — gates Sentry.captureException in ErrorBoundary.
 */
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Palette, Plug, Save, ShieldAlert, Gauge } from "lucide-react";
import { BackButton } from "@/components/BackButton";
import {
  getCustomRpcUrl,
  getGasLimit,
  getSentryEnabled,
  setCustomRpcUrl,
  setGasLimit,
  setSentryEnabled,
} from "@/lib/settings";

const palette = {
  input: {
    width: "100%",
    padding: "0.6rem 0.8rem",
    borderRadius: 10,
    border: "1px solid #3a4157",
    background: "#0b0f1a",
    color: "#e6e9f2",
    fontSize: "0.9rem",
    outline: "none",
  } as const,
  card: {
    padding: "1.3rem 1.5rem",
    borderRadius: 16,
    border: "1px solid #2a3150",
    background: "rgba(255,255,255,0.03)",
    marginTop: "1.2rem",
  } as const,
  save: {
    padding: "0.5rem 1.1rem",
    borderRadius: 10,
    border: "none",
    background: "#38BDF8",
    color: "#0b0f1a",
    fontSize: "0.85rem",
    fontWeight: 700,
    cursor: "pointer",
  } as const,
};

function Card({ icon, title, children }: { icon: React.ReactNode; title: string; children: React.ReactNode }) {
  return (
    <section style={palette.card}>
      <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600, marginBottom: "0.9rem" }}>
        {icon}
        {title}
      </div>
      {children}
    </section>
  );
}

export default function SettingsPage() {
  const [rpc, setRpc] = useState<string>(() => getCustomRpcUrl() ?? "");
  const [rpcStatus, setRpcStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [gas, setGas] = useState<string>(() => getGasLimit() ?? "");
  const [gasError, setGasError] = useState<string | null>(null);
  const [sentry, setSentry] = useState<boolean>(() => getSentryEnabled());
  const [savedFlash, setSavedFlash] = useState(false);

  useEffect(() => {
    if (!savedFlash) return;
    const t = setTimeout(() => setSavedFlash(false), 1600);
    return () => clearTimeout(t);
  }, [savedFlash]);

  const testRpc = async () => {
    setRpcStatus(null);
    try {
      const { createPublicClient, http } = await import("viem");
      const client = createPublicClient({ transport: http(rpc.trim() || undefined) });
      const chainId = await client.getChainId();
      setRpcStatus({ ok: true, text: `Connected — chain id ${chainId}` });
    } catch (e) {
      setRpcStatus({ ok: false, text: e instanceof Error ? e.message : "Connection failed" });
    }
  };

  const saveRpc = () => {
    const ok = setCustomRpcUrl(rpc);
    if (!ok) {
      setRpcStatus({ ok: false, text: "Invalid URL — use https:// or http://" });
      return;
    }
    setRpcStatus({ ok: true, text: "Saved — new RPC is used for live reads" });
    setSavedFlash(true);
  };

  const saveGas = () => {
    if (!setGasLimit(gas)) {
      setGasError("Enter a number ≥ 21000");
      return;
    }
    setGasError(null);
    setSavedFlash(true);
  };

  const toggleSentry = (enabled: boolean) => {
    setSentryEnabled(enabled);
    setSentry(enabled);
    setSavedFlash(true);
  };

  return (
    <main style={{ maxWidth: 760, margin: "0 auto", padding: "3rem 1.5rem 5rem" }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <BackButton />
        <h1 style={{ margin: "0 0 0.4rem", fontSize: "1.8rem" }}>Settings</h1>
        <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.95rem" }}>
          Network, transaction and diagnostics preferences. Everything is stored locally in your browser.
        </p>

        {savedFlash && (
          <div
            style={{
              marginTop: "1rem",
              padding: "0.6rem 1rem",
              borderRadius: 10,
              border: "1px solid rgba(95,211,140,0.4)",
              background: "rgba(95,211,140,0.08)",
              color: "#5fd38c",
              fontSize: "0.85rem",
            }}
          >
            Preferences saved.
          </div>
        )}

        <Card icon={<Plug size={16} style={{ color: "#38BDF8" }} />} title="Custom RPC endpoint">
          <input
            value={rpc}
            onChange={(e) => setRpc(e.target.value)}
            placeholder="https://coston2-api.flare.network/ext/C/rpc"
            style={palette.input}
            aria-label="Custom RPC URL"
          />
          <div style={{ display: "flex", gap: "0.6rem", marginTop: "0.7rem", alignItems: "center" }}>
            <button type="button" onClick={() => void testRpc()} style={palette.save}>
              Test connection
            </button>
            <button type="button" onClick={saveRpc} style={{ ...palette.save, background: "#4f6bff" }}>
              <Save size={14} style={{ verticalAlign: -2, marginRight: 4 }} /> Save
            </button>
            {rpcStatus && (
              <span style={{ color: rpcStatus.ok ? "#5fd38c" : "#ff9d9d", fontSize: "0.82rem" }}>
                {rpcStatus.text}
              </span>
            )}
          </div>
          <p style={{ color: "#6b7390", fontSize: "0.78rem", margin: "0.7rem 0 0" }}>
            The live feed readers use this endpoint for all Coston2 reads.
          </p>
        </Card>

        <Card icon={<Gauge size={16} style={{ color: "#38BDF8" }} />} title="Gas limit">
          <input
            value={gas}
            onChange={(e) => setGas(e.target.value)}
            placeholder="3000000"
            inputMode="numeric"
            style={palette.input}
            aria-label="Default gas limit"
          />
          {gasError && <div style={{ color: "#f87171", fontSize: "0.82rem", marginTop: "0.4rem" }}>{gasError}</div>}
          <div style={{ marginTop: "0.7rem" }}>
            <button type="button" onClick={saveGas} style={palette.save}>
              <Save size={14} style={{ verticalAlign: -2, marginRight: 4 }} /> Save
            </button>
          </div>
          <p style={{ color: "#6b7390", fontSize: "0.78rem", margin: "0.7rem 0 0" }}>
            Applied to wallet transactions sent from the AI Copilot deploy flow.
          </p>
        </Card>

        <Card icon={<Palette size={16} style={{ color: "#38BDF8" }} />} title="Personalization">
          <div style={{ display: "flex", alignItems: "center", gap: "0.7rem" }}>
            <span style={{ fontSize: "0.9rem" }}>Interface theme</span>
            <span
              style={{
                padding: "0.2rem 0.7rem",
                borderRadius: 999,
                border: "1px solid #3a4157",
                color: "#9aa3bf",
                fontSize: "0.78rem",
              }}
            >
              Dark (system default)
            </span>
          </div>
        </Card>

        <Card icon={<ShieldAlert size={16} style={{ color: "#38BDF8" }} />} title="Sentry SRE logging">
          <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
            <button
              type="button"
              role="switch"
              aria-checked={sentry}
              aria-label="Sentry logging"
              onClick={() => toggleSentry(!sentry)}
              style={{
                width: 46,
                height: 26,
                borderRadius: 999,
                border: "none",
                background: sentry ? "#38BDF8" : "#3a4157",
                position: "relative",
                cursor: "pointer",
                transition: "background 0.2s",
              }}
            >
              <span
                style={{
                  position: "absolute",
                  top: 3,
                  left: sentry ? 23 : 3,
                  width: 20,
                  height: 20,
                  borderRadius: "50%",
                  background: "#fff",
                  transition: "left 0.2s",
                }}
              />
            </button>
            <span style={{ fontSize: "0.9rem" }}>
              {sentry ? "Enabled — crashes report to Sentry" : "Disabled — crashes stay local"}
            </span>
          </div>
        </Card>
      </motion.div>
    </main>
  );
}

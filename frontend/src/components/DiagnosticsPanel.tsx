"use client";

/**
 * DiagnosticsPanel.tsx — admin-only diagnostics viewer.
 *
 * Errors NEVER render inline on the dashboard; they are reported to the
 * diagnostics store (src/lib/diagnostics.ts) and collected here, invisible
 * to regular users. The panel is fully hidden by default — no button, no
 * badge, no error count — so nothing leaks into the judge-facing UI.
 *
 * Admin reveal (any of these):
 *   - visit the dashboard with `?diag=1` in the URL (e.g. /?diag=1)
 *   - press Ctrl+Shift+D (toggles on/off)
 * Once enabled, the choice is remembered in localStorage for that browser.
 *
 * When open it offers:
 *   - Copy    — copies every entry as plain text (paste straight into chat)
 *   - Clear   — resets the collected entries
 *   - Refresh — re-checks live status endpoints and records the result
 *
 * The window-level handler (uncaught errors + unhandled rejections) is
 * installed on mount regardless of visibility, so errors are always
 * collected silently — they're just never shown to non-admins.
 */
import { useEffect, useState, useSyncExternalStore, type CSSProperties } from "react";
import { Bug, Copy, Check, RefreshCw, Trash2, X } from "lucide-react";
import {
  clearDiagnostics,
  copyDiagnostics,
  getDiagnostics,
  installGlobalDiagnostics,
  reportDiagnostic,
  subscribeDiagnostics,
  type DiagnosticsEntry,
} from "@/lib/diagnostics";

function entryColor(level: DiagnosticsEntry["level"]): string {
  return level === "error" ? "#ff9d9d" : level === "warn" ? "#ffb020" : "#9aa3bf";
}

const ADMIN_KEY = "frv.admin.v1";

function isAdminEnabled(): boolean {
  if (typeof window === "undefined") return false;
  const viaUrl = new URLSearchParams(window.location.search).has("diag");
  const viaStorage = window.localStorage.getItem(ADMIN_KEY) === "1";
  if (viaUrl) {
    try {
      window.localStorage.setItem(ADMIN_KEY, "1");
    } catch {
      // non-fatal
    }
  }
  return viaUrl || viaStorage;
}

export function DiagnosticsPanel() {
  const entries = useSyncExternalStore(subscribeDiagnostics, getDiagnostics, getDiagnostics);
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [admin, setAdmin] = useState(false);

  useEffect(() => {
    // Errors are ALWAYS collected — even when the panel is hidden.
    installGlobalDiagnostics();
    setAdmin(isAdminEnabled());

    // Secret toggle: Ctrl+Shift+D. Remembers the choice in localStorage.
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "d") {
        e.preventDefault();
        setAdmin((prev) => {
          const next = !prev;
          try {
            window.localStorage.setItem(ADMIN_KEY, next ? "1" : "0");
          } catch {
            // non-fatal
          }
          return next;
        });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Hidden for everyone unless admin mode is on.
  if (!admin) return null;

  const errorCount = entries.filter((e) => e.level === "error").length;

  const onCopy = async () => {
    const ok = await copyDiagnostics();
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  // Re-check the live endpoints so real failures are captured while the
  // panel is open — no need to reload the page.
  const onRefresh = async () => {
    setRefreshing(true);
    try {
      const [att, health] = await Promise.allSettled([
        fetch("/api/enclave/attestation", { cache: "no-store" }),
        fetch("/api/enclave/health", { cache: "no-store" }),
      ]);
      for (const [name, r] of [
        ["attestation", att],
        ["health", health],
      ] as const) {
        if (r.status === "rejected") {
          reportDiagnostic("error", `api/enclave/${name}`, "request failed", String(r.reason));
        } else {
          const body = (await r.value.json().catch(() => ({}))) as { detail?: string; status?: string };
          reportDiagnostic(
            r.value.status >= 500 ? "error" : "info",
            `api/enclave/${name}`,
            `HTTP ${r.value.status}${body.status ? ` · ${body.status}` : ""}`,
            body.detail
          );
        }
      }
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed",
        bottom: "1rem",
        right: "1rem",
        zIndex: 90,
        fontFamily: "system-ui, sans-serif",
      }}
    >
      {open && (
        <div
          style={{
            width: 460,
            maxWidth: "calc(100vw - 2rem)",
            maxHeight: "min(60vh, 420px)",
            display: "flex",
            flexDirection: "column",
            borderRadius: 14,
            border: "1px solid #2a3150",
            background: "rgba(13,17,28,0.97)",
            boxShadow: "0 18px 50px rgba(0,0,0,0.55)",
            overflow: "hidden",
            marginBottom: "0.6rem",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.7rem 0.9rem",
              borderBottom: "1px solid #2a3150",
            }}
          >
            <Bug size={15} style={{ color: "#4f6bff" }} />
            <strong style={{ fontSize: "0.9rem", color: "#e6e9f2" }}>Diagnostics</strong>
            <span style={{ fontSize: "0.75rem", color: "#6b7390" }}>
              {entries.length} event{entries.length === 1 ? "" : "s"}
              {errorCount > 0 ? ` · ${errorCount} error${errorCount === 1 ? "" : "s"}` : ""}
            </span>
            <div style={{ marginLeft: "auto", display: "flex", gap: "0.25rem" }}>
              <button
                onClick={() => void onRefresh()}
                title="Re-check live endpoints"
                aria-label="Refresh"
                style={panelBtn}
              >
                <RefreshCw size={14} className={refreshing ? "spin" : undefined} />
              </button>
              <button
                onClick={() => void onCopy()}
                title="Copy diagnostics to clipboard"
                aria-label="Copy diagnostics"
                style={panelBtn}
              >
                {copied ? <Check size={14} style={{ color: "#5fd38c" }} /> : <Copy size={14} />}
              </button>
              <button
                onClick={() => {
                  clearDiagnostics();
                }}
                title="Clear diagnostics"
                aria-label="Clear"
                style={panelBtn}
              >
                <Trash2 size={14} />
              </button>
              <button
                onClick={() => setOpen(false)}
                title="Close"
                aria-label="Close"
                style={panelBtn}
              >
                <X size={14} />
              </button>
            </div>
          </div>

          <div style={{ overflowY: "auto", flex: 1, padding: "0.5rem 0.75rem" }}>
            {entries.length === 0 ? (
              <p style={{ color: "#6b7390", fontSize: "0.82rem", padding: "0.6rem 0.2rem", margin: 0 }}>
                No errors recorded. Everything reported clean so far.
              </p>
            ) : (
              entries
                .slice()
                .reverse()
                .map((e) => (
                  <div
                    key={e.id}
                    style={{
                      borderBottom: "1px solid rgba(42,49,80,0.5)",
                      padding: "0.5rem 0.15rem",
                    }}
                  >
                    <div style={{ display: "flex", gap: "0.5rem", alignItems: "baseline" }}>
                      <span
                        style={{
                          color: entryColor(e.level),
                          fontSize: "0.68rem",
                          fontWeight: 700,
                          textTransform: "uppercase",
                          letterSpacing: "0.04em",
                          minWidth: 38,
                        }}
                      >
                        {e.level}
                      </span>
                      <span style={{ color: "#9aa3bf", fontSize: "0.72rem", fontFamily: "monospace" }}>
                        {e.ts.slice(11, 19)}
                      </span>
                      <span style={{ color: "#c9cfe4", fontSize: "0.8rem", fontFamily: "monospace" }}>
                        {e.source}
                      </span>
                    </div>
                    <p style={{ margin: "0.25rem 0 0", color: "#e6e9f2", fontSize: "0.82rem", lineHeight: 1.5 }}>
                      {e.message}
                    </p>
                    {e.detail && (
                      <pre
                        style={{
                          margin: "0.3rem 0 0",
                          color: "#8b93ab",
                          fontSize: "0.72rem",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                          lineHeight: 1.45,
                        }}
                      >
                        {e.detail}
                      </pre>
                    )}
                  </div>
                ))
            )}
          </div>
        </div>
      )}

      <button
        onClick={() => setOpen((o) => !o)}
        title={open ? "Hide diagnostics" : "Show diagnostics"}
        aria-label="Diagnostics"
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: "0.45rem",
          marginLeft: "auto",
          padding: "0.55rem 0.85rem",
          borderRadius: 999,
          border: "1px solid #2a3150",
          background: "rgba(13,17,28,0.9)",
          color: "#c9cfe4",
          fontSize: "0.8rem",
          fontWeight: 600,
          cursor: "pointer",
          boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
        }}
      >
        <Bug size={14} />
        Diagnostics
        {errorCount > 0 && (
          <span
            style={{
              background: "#e11d48",
              color: "#fff",
              borderRadius: 999,
              fontSize: "0.68rem",
              padding: "0.05rem 0.45rem",
              fontWeight: 700,
            }}
          >
            {errorCount}
          </span>
        )}
      </button>
    </div>
  );
}

const panelBtn: CSSProperties = {
  border: "none",
  background: "transparent",
  color: "#9aa3bf",
  cursor: "pointer",
  padding: "0.3rem",
  borderRadius: 8,
  display: "inline-flex",
};

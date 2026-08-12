"use client";

/**
 * SecureUploader.tsx — document upload with client-side envelope encryption
 * and BLIND PROXY transmission (Phase 9 / Prompts 169 + 174).
 *
 * Files are read in the browser and encrypted with AES-GCM-256 (Web Crypto,
 * see src/crypto/client_encryption.ts) BEFORE any transport — the plaintext
 * never leaves the browser unencrypted. On submit, ONLY the ciphertext
 * envelope is posted to the same-origin blind-proxy route
 * (api/enclave/query), which relays it to the enclave over HTTPS; the
 * browser never learns the enclave's address and nothing is cached locally
 * (no localStorage, no persistence — cache: "no-store" server-side).
 * The enclave's REAL response is displayed verbatim (encrypted response
 * envelope on success; the honest 4xx/5xx problem detail otherwise).
 */
import { useCallback, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { FileUp, Lock, Send, ShieldCheck, Trash2 } from "lucide-react";
import { encryptFileClientSide, type EncryptedFileResult } from "@/crypto/client_encryption";

const MAX_BYTES = 25 * 1024 * 1024; // 25 MB soft cap for the demo endpoint

interface ProxyResult {
  status: number;
  ok: boolean;
  body: {
    envelope?: string;
    status?: string;
    detail?: string;
    title?: string;
  };
}

export function SecureUploader({
  onExecutionRecord,
}: {
  /** Report the last real blind-proxy result to the dashboard (Prompt 172). */
  onExecutionRecord?: (record: {
    status: string;
    detail?: string;
    timestamp?: string;
  }) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EncryptedFileResult | null>(null);
  const [proxyResult, setProxyResult] = useState<ProxyResult | null>(null);

  const onFile = useCallback(async (file: File | undefined) => {
    setError(null);
    setProxyResult(null);
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setError(`File exceeds the ${MAX_BYTES / 1024 / 1024} MB demo cap.`);
      return;
    }
    setBusy(true);
    try {
      // REAL client-side encryption — the plaintext is wrapped in the browser.
      const encrypted = await encryptFileClientSide(file);
      setResult(encrypted);
    } catch (e) {
      setError((e as Error).message ?? "Encryption failed.");
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = "";
    }
  }, []);

  /**
   * P174 blind proxy: post ONLY the ciphertext envelope through the
   * server-side route. Never the plaintext; never cached locally.
   */
  const submitToEnclave = useCallback(async () => {
    if (!result) return;
    setSending(true);
    setProxyResult(null);
    setError(null);
    try {
      // Envelope wire format: base64(nonce || ciphertext || tag) — the same
      // contract the enclave's EncryptedQueryRequest decodes (Prompt 066).
      const bytes = new Uint8Array(result.envelope.ciphertext);
      const combined = new Uint8Array(12 + bytes.byteLength);
      combined.set(result.envelope.iv);
      combined.set(bytes, 12);

      const b64 = (() => {
        // Array.from works on array-likes at any TS target (no spread on
        // typed arrays — ES5-compatible, browser btoa-safe).
        const bin = Array.from(combined, (b) => String.fromCharCode(b)).join("");
        return btoa(bin);
      })();

      const res = await fetch("/api/enclave/query", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload: b64 }),
        cache: "no-store", // blind proxy: never cache ciphertext
      });
      const body = (await res.json().catch(() => ({}))) as ProxyResult["body"];
      setProxyResult({ status: res.status, ok: res.ok, body });
      onExecutionRecord?.({
        status: res.ok ? "ok" : "error",
        detail: res.ok
          ? `Encrypted response envelope received (${res.status})`
          : body.detail ?? body.title ?? `HTTP ${res.status}`,
        timestamp: new Date().toISOString(),
      });
    } catch (e) {
      setError((e as Error).message ?? "Proxy submission failed.");
      onExecutionRecord?.({
        status: "error",
        detail: (e as Error).message ?? "Proxy submission failed",
        timestamp: new Date().toISOString(),
      });
    } finally {
      setSending(false);
    }
  }, [result, onExecutionRecord]);

  return (
    <div
      style={{
        border: "1px solid #2a3150",
        borderRadius: 16,
        background: "rgba(255,255,255,0.03)",
        padding: "1.5rem",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.4rem" }}>
        <Lock size={18} style={{ color: "#5fd38c" }} />
        <h2 style={{ margin: 0, fontSize: "1.1rem" }}>Encrypted Document Upload</h2>
      </div>
      <p style={{ color: "#9aa3bf", fontSize: "0.9rem", margin: "0 0 1.25rem", lineHeight: 1.5 }}>
        Files are encrypted in your browser with AES-GCM-256 before they ever
        leave this page. The plaintext never touches the network.
      </p>

      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          onFile(e.dataTransfer.files?.[0]);
        }}
        onClick={() => inputRef.current?.click()}
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          gap: "0.6rem",
          padding: "2rem 1rem",
          borderRadius: 12,
          border: "1.5px dashed #3a4157",
          cursor: "pointer",
          transition: "border-color 0.2s, background 0.2s",
        }}
        onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "#4f6bff")}
        onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = "#3a4157")}
      >
        <FileUp size={28} style={{ color: "#4f6bff" }} />
        <span style={{ fontSize: "0.95rem" }}>Drop a document here or click to browse</span>
        <span style={{ color: "#6b7390", fontSize: "0.8rem" }}>
          Any file type · up to {MAX_BYTES / 1024 / 1024} MB
        </span>
        <input
          ref={inputRef}
          type="file"
          style={{ display: "none" }}
          onChange={(e) => onFile(e.target.files?.[0])}
        />
      </div>

      {busy && (
        <p style={{ color: "#9aa3bf", marginTop: "1rem", fontSize: "0.9rem" }}>
          Encrypting in browser…
        </p>
      )}
      {error && (
        <p style={{ color: "#ff9d9d", marginTop: "1rem", fontSize: "0.9rem" }}>{error}</p>
      )}

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{
              marginTop: "1.25rem",
              borderRadius: 12,
              border: "1px solid rgba(95, 211, 140, 0.35)",
              background: "rgba(95, 211, 140, 0.08)",
              padding: "1rem",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem" }}>
              <ShieldCheck size={17} style={{ color: "#5fd38c" }} />
              <strong style={{ fontSize: "0.95rem" }}>Encrypted in browser</strong>
              <button
                onClick={() => setResult(null)}
                aria-label="Clear"
                style={{
                  marginLeft: "auto",
                  border: "none",
                  background: "transparent",
                  color: "#9aa3bf",
                  cursor: "pointer",
                }}
              >
                <Trash2 size={15} />
              </button>
            </div>
            <dl style={{ margin: 0, display: "grid", gap: "0.35rem", fontSize: "0.85rem", color: "#c9cfe4" }}>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>File</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{result.fileName}</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>Plaintext size</dt>
                <dd style={{ margin: 0 }}>{result.plaintextSize} bytes</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>Ciphertext size</dt>
                <dd style={{ margin: 0 }}>{result.envelope.ciphertext.byteLength} bytes (+16 GCM tag)</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>Plaintext SHA-256</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{result.plaintextSha256.slice(0, 24)}…</dd>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <dt style={{ color: "#6b7390", minWidth: 150 }}>Envelope key fp</dt>
                <dd style={{ margin: 0, fontFamily: "monospace" }}>{result.keyFingerprint}…</dd>
              </div>
            </dl>
            <button
              onClick={() => void submitToEnclave()}
              disabled={sending}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.5rem",
                marginTop: "0.9rem",
                padding: "0.65rem 1.1rem",
                borderRadius: 10,
                border: "none",
                background: "linear-gradient(135deg, #4f6bff, #7a4fff)",
                color: "#fff",
                fontSize: "0.9rem",
                fontWeight: 600,
                cursor: sending ? "wait" : "pointer",
              }}
            >
              <Send size={15} />
              {sending ? "Submitting ciphertext…" : "Submit to enclave (blind proxy)"}
            </button>

            {proxyResult && (
              <div
                style={{
                  marginTop: "0.8rem",
                  borderRadius: 10,
                  border: `1px solid ${proxyResult.ok ? "rgba(95,211,140,0.35)" : "rgba(255,157,157,0.35)"}`,
                  background: proxyResult.ok
                    ? "rgba(95,211,140,0.07)"
                    : "rgba(255,157,157,0.07)",
                  padding: "0.75rem 0.9rem",
                  fontSize: "0.82rem",
                }}
              >
                <p style={{ margin: 0, color: proxyResult.ok ? "#5fd38c" : "#ff9d9d" }}>
                  Enclave responded HTTP {proxyResult.status}
                  {proxyResult.ok && proxyResult.body.envelope
                    ? ` — encrypted response envelope (${(proxyResult.body.envelope.length * 3 / 4).toFixed(0)} bytes b64) received`
                    : proxyResult.body.title
                      ? ` — ${proxyResult.body.title}`
                      : proxyResult.body.detail
                        ? ` — ${proxyResult.body.detail}`
                        : ""}
                </p>
                {!proxyResult.ok && proxyResult.body.detail && (
                  <p style={{ margin: "0.35rem 0 0", color: "#9aa3bf", lineHeight: 1.5 }}>
                    {proxyResult.body.detail}
                  </p>
                )}
              </div>
            )}

            <p style={{ margin: "0.75rem 0 0", color: "#9aa3bf", fontSize: "0.8rem", lineHeight: 1.5 }}>
              Only the ciphertext envelope is transmitted — through the
              same-origin blind proxy over HTTPS. Nothing is stored locally;
              the envelope key stays in this browser session until the
              attested key exchange.
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

"use client";

/**
 * CopilotDrawer.tsx — Local AI Developer Copilot (Phase 18, P341-349).
 *
 * Slide-out assistant drawer (Framer Motion, initial={{ x: "100%" }} →
 * 0, P349) opened by the header's "AI Copilot" FAB (P348). Questions are
 * answered by the copilot engine running in a REAL Web Worker (P353) — the
 * browser thread only renders. Generated artifacts:
 *   • FDC Web2Json selectors with the ABI-encoded request hex (P344)
 *   • Solidity boilerplate matching the repo's IFdcVerification / IFtsoV2
 *     interfaces (P345)
 *   • One-Click Deploy: prepares the MIC-bearing request via the official
 *     Flare verifier, resolves FdcHub + fee live from Coston2, and hands the
 *     transaction to the connected wallet (P346)
 * Code blocks are syntax-highlighted (P347) with copy buttons (P356); the
 * drawer greets the user by their saved display name.
 */
import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { useTranslations } from "next-intl";
import { Bot, CircleHelp, Copy, Rocket, Send, User, X } from "lucide-react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";
import { useAccount, useSendTransaction } from "wagmi";
import { CopilotHelpModal } from "@/components/CopilotHelpModal";
import { OPEN_COPILOT_EVENT } from "@/components/Header";
import { useUserName } from "@/lib/user_profile";
import { prepareFdcDeploy } from "@/lib/fdc_deploy";
import { getGasLimit } from "@/lib/settings";
import { reportDiagnostic } from "@/lib/diagnostics";
import type { CopilotWorkerRequest, CopilotWorkerResponse } from "@/workers/copilot.worker";

interface Message {
  id: number;
  role: "user" | "assistant";
  text: string;
  code?: string;
  config?: {
    abiEncodedRequest?: string;
    byteLength?: number;
    url?: string;
    postProcessJq?: string;
    abiSignature?: string;
  };
}

let msgId = 1;

export function CopilotDrawer() {
  const { address, isConnected } = useAccount();
  const name = useUserName(address);
  const t = useTranslations();
  const { sendTransactionAsync } = useSendTransaction();

  const [open, setOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [deployMsg, setDeployMsg] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<number | null>(null);

  const workerRef = useRef<Worker | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const greetedRef = useRef(false);

  // Greet once, by the user's saved name.
  useEffect(() => {
    if (open && !greetedRef.current) {
      greetedRef.current = true;
      setMessages((m) => [
        ...m,
        {
          id: msgId++,
          role: "assistant",
          text: t("copilot.welcome", { name }),
        },
      ]);
    }
  }, [open, name]);

  // Worker lifecycle (P353) — the engine runs entirely off the main thread.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const worker = new Worker(new URL("../workers/copilot.worker.ts", import.meta.url));
    workerRef.current = worker;
    worker.onmessage = (event: MessageEvent<CopilotWorkerResponse>) => {
      const { result } = event.data;
      setBusy(false);
      // Direct generator results (ok-discriminated) surface their artifact.
      if ("ok" in result) {
        if (!result.ok) {
          setMessages((m) => [
            ...m,
            { id: msgId++, role: "assistant", text: result.error },
          ]);
          return;
        }
        const g = result as {
          ok: true;
          code?: string;
          abiEncodedRequest?: string;
          byteLength?: number;
          url?: string;
          postProcessJq?: string;
          abiSignature?: string;
          note?: string;
        };
        setMessages((m) => [
          ...m,
          {
            id: msgId++,
            role: "assistant",
            text: g.note ?? "Generated artifact:",
            code: g.code,
            config: g.abiEncodedRequest
              ? {
                  abiEncodedRequest: g.abiEncodedRequest,
                  byteLength: g.byteLength,
                  url: g.url,
                  postProcessJq: g.postProcessJq,
                  abiSignature: g.abiSignature,
                }
              : undefined,
          },
        ]);
        return;
      }
      const r = result;
      if (r.kind === "fdc-selector") {
        const cfg = r.config;
        if (cfg) {
          setMessages((m) => [
            ...m,
            {
              id: msgId++,
              role: "assistant",
              text: r.text,
              config: {
                abiEncodedRequest: cfg.abiEncodedRequest,
                byteLength: cfg.byteLength,
                url: cfg.url,
                postProcessJq: cfg.postProcessJq,
                abiSignature: cfg.abiSignature,
              },
            },
          ]);
          return;
        }
      }
      setMessages((m) => [
        ...m,
        { id: msgId++, role: "assistant", text: r.text, code: r.code },
      ]);
    };
    worker.onerror = (e) => {
      setBusy(false);
      reportDiagnostic("error", "CopilotDrawer", "copilot worker error", e.message);
      setMessages((m) => [
        ...m,
        { id: msgId++, role: "assistant", text: "The local engine hit an error — see the diagnostics panel." },
      ]);
    };
    return () => worker.terminate();
  }, []);

  // Open via header FAB event.
  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener(OPEN_COPILOT_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_COPILOT_EVENT, onOpen);
  }, []);

  // Auto-scroll to the newest message.
  useEffect(() => {
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [messages]);

  const submit = () => {
    const q = input.trim();
    if (!q || busy) return;
    setMessages((m) => [...m, { id: msgId++, role: "user", text: q }]);
    setInput("");
    setBusy(true);
    const req: CopilotWorkerRequest = { id: Date.now(), type: "query", query: q };
    workerRef.current?.postMessage(req);
  };

  const copy = async (msg: Message) => {
    const text = msg.config?.abiEncodedRequest ?? msg.code ?? msg.text;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(msg.id);
      setTimeout(() => setCopiedId(null), 1500);
    } catch {
      reportDiagnostic("warn", "CopilotDrawer", "clipboard write failed");
    }
  };

  const deploy = async (msg: Message) => {
    if (!msg.config?.url || !msg.config.postProcessJq || !msg.config.abiSignature) return;
    if (!isConnected || !address) {
      setDeployMsg("Connect a wallet first — the request is submitted from your Coston2 account.");
      return;
    }
    setDeploying(true);
    setDeployMsg(null);
    try {
      const prepared = await prepareFdcDeploy(
        msg.config.url,
        msg.config.postProcessJq,
        msg.config.abiSignature
      );
      const gasLimit = getGasLimit();
      const hash = await sendTransactionAsync({
        to: prepared.to,
        data: prepared.data,
        value: prepared.value,
        ...(gasLimit ? { gas: BigInt(gasLimit) } : {}),
      });
      setDeployMsg(
        `Request submitted — tx ${hash.slice(0, 10)}…${hash.slice(-6)}. Voting round finalizes in ~90s; verify on the Coston2 explorer.`
      );
      reportDiagnostic("info", "CopilotDrawer", "FDC request submitted", hash);
    } catch (e) {
      setDeployMsg(e instanceof Error ? `Deploy failed: ${e.message}` : "Deploy failed");
      reportDiagnostic("error", "CopilotDrawer", "FDC deploy failed", e instanceof Error ? e.message : String(e));
    } finally {
      setDeploying(false);
    }
  };

  return (
    <>
      <AnimatePresence>
        {open && (
          <motion.aside
            role="dialog"
            aria-label="AI Copilot"
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "tween", duration: 0.28, ease: "easeOut" }}
            style={{
              position: "fixed",
              top: 0,
              right: 0,
              bottom: 0,
              width: "min(420px, 100vw)",
              zIndex: 80,
              display: "flex",
              flexDirection: "column",
              background: "#0f1526",
              borderLeft: "1px solid #1E293B",
              boxShadow: "-24px 0 60px rgba(0,0,0,0.5)",
            }}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.6rem",
                padding: "1rem 1.1rem",
                borderBottom: "1px solid #1c2237",
              }}
            >
              <Bot size={19} style={{ color: "#38BDF8" }} />
              <span style={{ fontWeight: 700, fontSize: "1rem" }}>AI Copilot</span>
              <button
                type="button"
                onClick={() => setHelpOpen(true)}
                aria-label="Copilot help"
                title="How to use"
                style={{
                  marginLeft: "auto",
                  border: "none",
                  background: "transparent",
                  color: "#9aa3bf",
                  cursor: "pointer",
                  padding: 4,
                }}
              >
                <CircleHelp size={17} />
              </button>
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close copilot"
                style={{
                  border: "none",
                  background: "transparent",
                  color: "#9aa3bf",
                  cursor: "pointer",
                  padding: 4,
                }}
              >
                <X size={17} />
              </button>
            </div>

            <div
              ref={listRef}
              style={{
                flex: 1,
                overflowY: "auto",
                padding: "1rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.8rem",
              }}
            >
              {messages.length === 0 && (
                <div style={{ color: "#6b7390", fontSize: "0.85rem", lineHeight: 1.6 }}>
                  Ask me to generate an FDC selector, Solidity boilerplate, or the
                  FTSO v2 feed ids. Everything runs locally.
                </div>
              )}
              {messages.map((m) => (
                <div
                  key={m.id}
                  style={{
                    alignSelf: m.role === "user" ? "flex-end" : "flex-start",
                    maxWidth: "92%",
                    padding: "0.7rem 0.9rem",
                    borderRadius: 14,
                    border: m.role === "user" ? "1px solid #38BDF8" : "1px solid #2a3150",
                    background: m.role === "user" ? "rgba(56,189,248,0.12)" : "rgba(255,255,255,0.03)",
                    color: "#e6e9f2",
                    fontSize: "0.86rem",
                    lineHeight: 1.55,
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                  }}
                >
                  {m.role === "user" ? (
                    <div style={{ display: "flex", gap: "0.4rem", alignItems: "flex-start" }}>
                      <User size={13} style={{ marginTop: 3, color: "#38BDF8", flexShrink: 0 }} />
                      <span>{m.text}</span>
                    </div>
                  ) : (
                    <>
                      <span>{m.text}</span>

                      {m.config && (
                        <div
                          style={{
                            marginTop: "0.7rem",
                            padding: "0.7rem 0.8rem",
                            borderRadius: 10,
                            border: "1px solid #1E293B",
                            background: "#0b0f1a",
                            fontFamily: "monospace",
                            fontSize: "0.72rem",
                            color: "#9aa3bf",
                            wordBreak: "break-all",
                          }}
                        >
                          <div>
                            {m.config.url} · jq {m.config.postProcessJq} · {m.config.abiSignature}
                          </div>
                          <div style={{ marginTop: "0.4rem", color: "#7cc7ff" }}>
                            {m.config.byteLength} bytes · {m.config.abiEncodedRequest?.slice(0, 42)}…
                          </div>
                        </div>
                      )}

                      {m.code && (
                        <div style={{ marginTop: "0.7rem", borderRadius: 10, overflow: "hidden" }}>
                          <SyntaxHighlighter
                            language="solidity"
                            style={oneDark}
                            customStyle={{
                              margin: 0,
                              padding: "0.8rem",
                              fontSize: "0.72rem",
                              background: "#0b0f1a",
                              maxHeight: 320,
                            }}
                          >
                            {m.code}
                          </SyntaxHighlighter>
                        </div>
                      )}

                      <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.6rem" }}>
                        <button
                          type="button"
                          onClick={() => void copy(m)}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.3rem",
                            padding: "0.3rem 0.7rem",
                            borderRadius: 8,
                            border: "1px solid #2a3150",
                            background: "transparent",
                            color: "#9aa3bf",
                            fontSize: "0.75rem",
                            cursor: "pointer",
                          }}
                        >
                          <Copy size={12} />
                          {copiedId === m.id ? "Copied" : "Copy"}
                        </button>
                        {m.config && (
                          <button
                            type="button"
                            onClick={() => void deploy(m)}
                            disabled={deploying}
                            style={{
                              display: "inline-flex",
                              alignItems: "center",
                              gap: "0.3rem",
                              padding: "0.3rem 0.7rem",
                              borderRadius: 8,
                              border: "none",
                              background: "#38BDF8",
                              color: "#0b0f1a",
                              fontSize: "0.75rem",
                              fontWeight: 700,
                              cursor: deploying ? "wait" : "pointer",
                            }}
                          >
                            <Rocket size={12} />
                            {deploying ? "Submitting…" : "One-Click Deploy"}
                          </button>
                        )}
                      </div>

                      {m.id === messages[messages.length - 1]?.id && deployMsg && (
                        <div
                          style={{
                            marginTop: "0.6rem",
                            padding: "0.5rem 0.7rem",
                            borderRadius: 8,
                            border: "1px solid rgba(56,189,248,0.3)",
                            background: "rgba(56,189,248,0.06)",
                            color: "#7cc7ff",
                            fontSize: "0.75rem",
                            lineHeight: 1.5,
                          }}
                        >
                          {deployMsg}
                        </div>
                      )}
                    </>
                  )}
                </div>
              ))}
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
              style={{
                display: "flex",
                gap: "0.5rem",
                padding: "0.9rem 1rem",
                borderTop: "1px solid #1c2237",
              }}
            >
              <input
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder={t("copilot.placeholder", { name })}
                aria-label="Copilot question"
                style={{
                  flex: 1,
                  padding: "0.6rem 0.8rem",
                  borderRadius: 10,
                  border: "1px solid #2a3150",
                  background: "#0b0f1a",
                  color: "#e6e9f2",
                  fontSize: "0.88rem",
                  outline: "none",
                }}
              />
              <button
                type="submit"
                disabled={busy || input.trim().length === 0}
                aria-label="Send"
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  width: 42,
                  borderRadius: 10,
                  border: "none",
                  background: busy ? "#3a4157" : "#38BDF8",
                  color: "#0b0f1a",
                  cursor: busy ? "wait" : "pointer",
                }}
              >
                <Send size={16} />
              </button>
            </form>
          </motion.aside>
        )}
      </AnimatePresence>

      <CopilotHelpModal open={helpOpen} onOpenChange={setHelpOpen} />
    </>
  );
}

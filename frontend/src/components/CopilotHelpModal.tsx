"use client";

/**
 * CopilotHelpModal.tsx — user guide for the AI Copilot (Phase 18, P352).
 * Radix Dialog + Framer Motion, documents sample prompts.
 */
import * as Dialog from "@radix-ui/react-dialog";
import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";

const SAMPLES = [
  {
    q: "FDC selector for https://jsonplaceholder.typicode.com/todos/1 with .completed as bool",
    a: "Builds a Web2Json request: validates the URL + jq path, generates the ABI-encoded request, and shows the exact bytes the repo's request_fdc_attestation.ts submits.",
  },
  {
    q: "Solidity boilerplate for Web2Json",
    a: "Emits a consumer contract matching this repo's IFdcVerification.sol — same verifyWeb2Json selector and proof layout.",
  },
  {
    q: "Solidity boilerplate for FtsoV2",
    a: "Emits a feed reader matching IFtsoV2.sol — getFeedById(bytes21) returning value/decimals/timestamp.",
  },
  {
    q: "list FTSO v2 feeds",
    a: "Shows the deterministic bytes21 feed ids (XRP/USD, BTC/USD, ETH/USD, FLR/USD) with the live-read contract code.",
  },
];

export function CopilotHelpModal({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(5,8,15,0.72)",
            zIndex: 90,
            backdropFilter: "blur(2px)",
          }}
        />
        <AnimatePresence>
          {open && (
            <Dialog.Content asChild>
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                transition={{ duration: 0.2 }}
                style={{
                  position: "fixed",
                  top: "50%",
                  left: "50%",
                  transform: "translate(-50%, -50%)",
                  width: "min(560px, calc(100vw - 2rem))",
                  maxHeight: "80vh",
                  overflowY: "auto",
                  zIndex: 91,
                  borderRadius: 18,
                  border: "1px solid #1E293B",
                  background: "#111827",
                  color: "#e6e9f2",
                  padding: "1.5rem",
                  boxShadow: "0 32px 80px rgba(0,0,0,0.6)",
                }}
              >
                <Dialog.Title style={{ margin: "0 0 0.4rem", fontSize: "1.2rem" }}>
                  AI Copilot — how to use it
                </Dialog.Title>
                <Dialog.Description asChild>
                  <p style={{ margin: "0 0 1rem", color: "#9aa3bf", fontSize: "0.88rem", lineHeight: 1.6 }}>
                    The copilot generates <strong>real protocol artifacts</strong> for Flare&apos;s
                    Data Connector and FTSO v2 — matching this repo&apos;s interfaces. It runs 100%
                    locally in a Web Worker: no AI API, nothing leaves your browser.
                  </p>
                </Dialog.Description>

                <div style={{ display: "grid", gap: "0.8rem" }}>
                  {SAMPLES.map((s) => (
                    <div
                      key={s.q}
                      style={{
                        padding: "0.9rem 1rem",
                        borderRadius: 12,
                        border: "1px solid #2a3150",
                        background: "rgba(255,255,255,0.03)",
                      }}
                    >
                      <div style={{ fontFamily: "monospace", fontSize: "0.82rem", color: "#7cc7ff" }}>
                        “{s.q}”
                      </div>
                      <div style={{ marginTop: "0.4rem", fontSize: "0.82rem", color: "#c9cfe4", lineHeight: 1.55 }}>
                        {s.a}
                      </div>
                    </div>
                  ))}
                </div>

                <Dialog.Close asChild>
                  <button
                    type="button"
                    aria-label="Close help"
                    style={{
                      position: "absolute",
                      top: 12,
                      right: 12,
                      border: "none",
                      background: "transparent",
                      color: "#9aa3bf",
                      cursor: "pointer",
                      padding: 4,
                    }}
                  >
                    <X size={16} />
                  </button>
                </Dialog.Close>
              </motion.div>
            </Dialog.Content>
          )}
        </AnimatePresence>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

"use client";

/**
 * WalletConnectOverlay.tsx — beautiful animated wallet connection flow.
 *
 * When the user clicks Connect Wallet and selects a wallet:
 * 1. Detects which wallet was selected (MetaMask, Phantom, etc.)
 * 2. Shows the wallet's logo with a spinning ring animation
 * 3. Displays "Confirming wallet connection..." while spinning
 * 4. Transitions to "Wallet connection confirmed" with a checkmark
 *
 * Everything runs client-side — no network calls, no API keys.
 */
import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check, Download } from "lucide-react";

interface WalletInfo {
  name: string;
  color: string;
  logo: string; // SVG data URI or emoji fallback
}

// Known wallet logos (inline SVGs as data URIs — zero network calls)
const WALLETS: Record<string, WalletInfo> = {
  metamask: {
    name: "MetaMask",
    color: "#f6851b",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#f6851b"/><text x="20" y="26" text-anchor="middle" font-size="22" fill="white">🦊</text></svg>`)}`,
  },
  phantom: {
    name: "Phantom",
    color: "#ab9ff2",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#ab9ff2"/><text x="20" y="26" text-anchor="middle" font-size="22" fill="white">👻</text></svg>`)}`,
  },
  coinbase: {
    name: "Coinbase Wallet",
    color: "#0052ff",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#0052ff"/><text x="20" y="26" text-anchor="middle" font-size="22" fill="white">🔵</text></svg>`)}`,
  },
  walletconnect: {
    name: "WalletConnect",
    color: "#3b99fc",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#3b99fc"/><text x="20" y="26" text-anchor="middle" font-size="20" fill="white">🔗</text></svg>`)}`,
  },
  rainbow: {
    name: "Rainbow",
    color: "#ff6b6b",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="linear-gradient(135deg,#ff6b6b,#ffd93d)"/><defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff6b6b"/><stop offset="100%" stop-color="#ffd93d"/></linearGradient></defs><rect width="40" height="40" rx="10" fill="url(#rg)"/><text x="20" y="26" text-anchor="middle" font-size="20" fill="white">🌈</text></svg>`)}`,
  },
  trust: {
    name: "Trust Wallet",
    color: "#3375bb",
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#3375bb"/><text x="20" y="26" text-anchor="middle" font-size="20" fill="white">🛡️</text></svg>`)}`,
  },
};

const DEFAULT_WALLET: WalletInfo = {
  name: "Wallet",
  color: "#4f6bff",
  logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><rect width="40" height="40" rx="10" fill="#4f6bff"/><text x="20" y="26" text-anchor="middle" font-size="20" fill="white">💳</text></svg>`)}`,
};

function detectWallet(): WalletInfo {
  if (typeof window === "undefined") return DEFAULT_WALLET;
  const eth: any = (window as any).ethereum;
  if (!eth) return DEFAULT_WALLET;

  // Check provider map first (RainbowKit injects providers)
  if (eth.providerMap && typeof eth.providerMap.keys === "function") {
    try {
      const keys = Array.from(eth.providerMap.keys()) as string[];
      const found = keys.find((k: string) =>
        k.toLowerCase().includes("metamask") || k.toLowerCase().includes("phantom")
      );
      if (found) {
        const lower = found.toLowerCase();
        if (lower.includes("metamask")) return WALLETS.metamask;
        if (lower.includes("phantom")) return WALLETS.phantom;
      }
    } catch {
      // providerMap iterable failed — fall through to property checks
    }
  }

  // Direct property checks
  if (eth.isMetaMask) return WALLETS.metamask;
  if (eth.isPhantom) return WALLETS.phantom;
  if (eth.isCoinbaseWallet) return WALLETS.coinbase;
  if (eth.isTrust) return WALLETS.trust;
  return DEFAULT_WALLET;
}

interface Props {
  connecting: boolean;
  connected: boolean;
}

export function WalletConnectOverlay({ connecting, connected }: Props) {
  const [wallet, setWallet] = useState<WalletInfo>(DEFAULT_WALLET);
  const [phase, setPhase] = useState<"idle" | "connecting" | "confirmed">("idle");
  const [showConfirming, setShowConfirming] = useState(false);

  // Detect wallet when connecting starts
  useEffect(() => {
    if (connecting) {
      setWallet(detectWallet());
      setPhase("connecting");
      setShowConfirming(true);
    }
  }, [connecting]);

  // Transition to confirmed after connection succeeds
  useEffect(() => {
    if (connected && phase === "connecting") {
      // Short delay so the user sees "confirmed" before the overlay fades
      const t = setTimeout(() => setPhase("confirmed"), 300);
      const t2 = setTimeout(() => setShowConfirming(false), 2500);
      return () => { clearTimeout(t); clearTimeout(t2); };
    }
  }, [connected, phase]);

  // Reset when disconnected
  useEffect(() => {
    if (!connected && !connecting) {
      setPhase("idle");
      setShowConfirming(false);
    }
  }, [connected, connecting]);

  return (
    <AnimatePresence>
      {showConfirming && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 200,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "rgba(0,0,0,0.7)",
            backdropFilter: "blur(10px)",
          }}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            transition={{ type: "spring", damping: 20, stiffness: 300 }}
            style={{
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              gap: "1.5rem",
              padding: "3rem",
              borderRadius: 24,
              border: "1px solid #2a3150",
              background: "linear-gradient(180deg, #111827 0%, #0b0f1a 100%)",
              boxShadow: `0 0 80px ${wallet.color}22`,
              minWidth: 320,
            }}
          >
            {/* Wallet logo with spinning ring */}
            <div style={{ position: "relative", width: 100, height: 100 }}>
              {/* Spinning ring */}
              {phase === "connecting" && (
                <svg
                  viewBox="0 0 100 100"
                  style={{
                    position: "absolute",
                    inset: 0,
                    width: 100,
                    height: 100,
                    animation: "walletSpin 1.2s linear infinite",
                  }}
                >
                  <circle
                    cx="50"
                    cy="50"
                    r="44"
                    fill="none"
                    stroke={wallet.color}
                    strokeWidth="3"
                    strokeLinecap="round"
                    strokeDasharray="200 80"
                    opacity="0.9"
                  />
                </svg>
              )}

              {/* Success ring */}
              {phase === "confirmed" && (
                <motion.div
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  style={{
                    position: "absolute",
                    inset: 0,
                    width: 100,
                    height: 100,
                    borderRadius: "50%",
                    border: `3px solid #5fd38c`,
                    boxShadow: `0 0 30px rgba(95,211,140,0.4)`,
                  }}
                />
              )}

              {/* Wallet logo */}
              <motion.div
                animate={phase === "connecting" ? { rotate: 0 } : { scale: [0.9, 1.05, 1] }}
                transition={phase === "confirmed" ? { duration: 0.4 } : undefined}
                style={{
                  position: "absolute",
                  inset: 10,
                  borderRadius: 20,
                  overflow: "hidden",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: `${wallet.color}22`,
                  border: `2px solid ${wallet.color}44`,
                }}
              >
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={wallet.logo}
                  alt={wallet.name}
                  width={60}
                  height={60}
                  style={{ borderRadius: 14 }}
                />
              </motion.div>
            </div>

            {/* Wallet name */}
            <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#e6e9f2" }}>
              {wallet.name}
            </div>

            {/* Status text */}
            <AnimatePresence mode="wait">
              {phase === "connecting" && (
                <motion.div
                  key="connecting"
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: "0.3rem",
                  }}
                >
                  <span style={{ color: "#9aa3bf", fontSize: "0.9rem" }}>
                    Confirming wallet connection…
                  </span>
                  <span style={{ color: "#6b7390", fontSize: "0.75rem" }}>
                    Please approve in your wallet
                  </span>
                </motion.div>
              )}

              {phase === "confirmed" && (
                <motion.div
                  key="confirmed"
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -5 }}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.5rem",
                    padding: "0.5rem 1.2rem",
                    borderRadius: 999,
                    background: "rgba(95,211,140,0.12)",
                    border: "1px solid rgba(95,211,140,0.3)",
                  }}
                >
                  <Check size={16} style={{ color: "#5fd38c" }} />
                  <span style={{ color: "#5fd38c", fontSize: "0.9rem", fontWeight: 600 }}>
                    Wallet connection confirmed
                  </span>
                </motion.div>
              )}
            </AnimatePresence>
          </motion.div>
        </motion.div>
      )}

      <style>{`
        @keyframes walletSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </AnimatePresence>
  );
}

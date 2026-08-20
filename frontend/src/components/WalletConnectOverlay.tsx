"use client";

/**
 * WalletConnectOverlay.tsx — animated wallet connection flow.
 *
 * Flow:
 * 1. User clicks Connect → spinner + "Confirming wallet connection…" (5 seconds)
 * 2. Wallet approves → green ring + "Wallet connection confirmed" + Continue button
 * 3. User taps Continue → overlay disappears instantly
 *
 * The spinner is VISUALLY OBVIOUS — a large CSS-animated arc that
 * rotates continuously for the full 5 seconds.
 */
import { useEffect, useState, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check } from "lucide-react";
import { useTranslations } from "next-intl";

interface WalletInfo {
  name: string;
  color: string;
  logo: string;
}

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
    logo: `data:image/svg+xml,${encodeURIComponent(`<svg viewBox="0 0 40 40" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="rg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#ff6b6b"/><stop offset="100%" stop-color="#ffd93d"/></linearGradient></defs><rect width="40" height="40" rx="10" fill="url(#rg)"/><text x="20" y="26" text-anchor="middle" font-size="20" fill="white">🌈</text></svg>`)}`,
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
      // fall through
    }
  }

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

/** Minimum milliseconds the spinner is visible — even if wallet
 *  connects instantly, the user sees a satisfying 5-second animation. */
const SPINNER_DURATION_MS = 5000;

export function WalletConnectOverlay({ connecting, connected }: Props) {
  const [wallet, setWallet] = useState<WalletInfo>(DEFAULT_WALLET);
  const [visible, setVisible] = useState(false);
  const [phase, setPhase] = useState<"spinner" | "confirmed">("spinner");
  const t = useTranslations();
  const connectStartedAt = useRef(0);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Detect wallet when connecting starts ──
  useEffect(() => {
    if (connecting) {
      setWallet(detectWallet());
      setPhase("spinner");
      setVisible(true);
      connectStartedAt.current = Date.now();
    }
  }, [connecting]);

  // ── When wallet reports connected, wait until 5 seconds have passed,
  //    THEN show confirmed. This guarantees the spinner is always visible. ──
  useEffect(() => {
    if (!connected || !visible || phase !== "spinner") return;

    const elapsed = Date.now() - connectStartedAt.current;
    const remaining = Math.max(0, SPINNER_DURATION_MS - elapsed);

    // Clear any previous timer
    if (timerRef.current) clearTimeout(timerRef.current);

    timerRef.current = setTimeout(() => {
      setPhase("confirmed");
    }, remaining);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [connected, visible, phase]);

  // ── Dismiss overlay — called ONLY by Continue button ──
  const dismiss = useCallback(() => {
    setVisible(false);
    setPhase("spinner");
  }, []);

  // ── Reset if wallet disconnects while overlay is showing ──
  useEffect(() => {
    if (!connected && !connecting) {
      setVisible(false);
      setPhase("spinner");
    }
  }, [connected, connecting]);

  return (
    <AnimatePresence>
      {visible && (
        <motion.div
          key="wallet-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.2 }}
          style={{
            position: "fixed",
            inset: 0,
            zIndex: 200,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "rgba(0,0,0,0.80)",
            backdropFilter: "blur(12px)",
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
            {/* ── Wallet logo + spinner / check ── */}
            <div style={{ position: "relative", width: 120, height: 120 }}>
              {/* SPINNING RING — large, obvious, CSS-animated */}
              {phase === "spinner" && (
                <>
                  {/* Outer spinning arc */}
                  <div
                    className="wallet-spinner"
                    style={{
                      position: "absolute",
                      inset: 0,
                      width: 120,
                      height: 120,
                      borderRadius: "50%",
                      border: `4px solid transparent`,
                      borderTopColor: wallet.color,
                      borderRightColor: `${wallet.color}88`,
                    }}
                  />
                  {/* Inner counter-spinning arc for depth */}
                  <div
                    className="wallet-spinner-reverse"
                    style={{
                      position: "absolute",
                      inset: 12,
                      width: 96,
                      height: 96,
                      borderRadius: "50%",
                      border: `3px solid transparent`,
                      borderBottomColor: `${wallet.color}66`,
                      borderLeftColor: `${wallet.color}33`,
                    }}
                  />
                  {/* Pulsing glow behind wallet logo */}
                  <div
                    className="wallet-pulse"
                    style={{
                      position: "absolute",
                      inset: 20,
                      borderRadius: 20,
                      background: `${wallet.color}15`,
                    }}
                  />
                </>
              )}

              {/* GREEN CHECK RING — confirmed */}
              {phase === "confirmed" && (
                <motion.div
                  initial={{ scale: 0.6, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  transition={{ type: "spring", damping: 12, stiffness: 200 }}
                  style={{
                    position: "absolute",
                    inset: 0,
                    width: 120,
                    height: 120,
                    borderRadius: "50%",
                    border: "4px solid #5fd38c",
                    boxShadow: "0 0 40px rgba(95,211,140,0.5)",
                  }}
                />
              )}

              {/* Wallet logo image */}
              <div
                style={{
                  position: "absolute",
                  inset: 16,
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
                  width={72}
                  height={72}
                  style={{ borderRadius: 14 }}
                />
              </div>
            </div>

            {/* Wallet name */}
            <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#e6e9f2" }}>
              {wallet.name}
            </div>

            {/* ── SPINNER STATE ── */}
            {phase === "spinner" && (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "0.3rem" }}>
                <span style={{ color: "#9aa3bf", fontSize: "0.9rem" }}>
                  {t("overlay.confirming", { defaultMessage: "Confirming wallet connection…" })}
                </span>
                <span style={{ color: "#6b7390", fontSize: "0.75rem" }}>
                  {t("overlay.approve", { defaultMessage: "Please approve in your wallet" })}
                </span>
              </div>
            )}

            {/* ── CONFIRMED STATE ── */}
            {phase === "confirmed" && (
              <motion.div
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
                style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "1rem" }}
              >
                {/* Success badge */}
                <div
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
                    {t("overlay.confirmed", { defaultMessage: "Wallet connection confirmed" })}
                  </span>
                </div>

                {/* CONTINUE BUTTON — user must tap to dismiss */}
                <button
                  onClick={dismiss}
                  style={{
                    padding: "0.75rem 2.5rem",
                    borderRadius: 12,
                    border: "none",
                    background: "linear-gradient(135deg, #4f6bff 0%, #38BDF8 100%)",
                    color: "#fff",
                    fontSize: "1rem",
                    fontWeight: 700,
                    cursor: "pointer",
                    letterSpacing: "0.02em",
                    boxShadow: "0 4px 20px rgba(79,107,255,0.4)",
                    transition: "transform 0.15s ease, box-shadow 0.15s ease",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.transform = "scale(1.03)";
                    e.currentTarget.style.boxShadow = "0 6px 28px rgba(79,107,255,0.55)";
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.transform = "scale(1)";
                    e.currentTarget.style.boxShadow = "0 4px 20px rgba(79,107,255,0.4)";
                  }}
                >
                  {t("overlay.continue", { defaultMessage: "Continue" })}
                </button>
              </motion.div>
            )}
          </motion.div>
        </motion.div>
      )}

      {/* CSS animations — defined at top level so they always exist in the DOM */}
      <style>{`
        .wallet-spinner {
          animation: walletSpin 1s linear infinite;
        }
        .wallet-spinner-reverse {
          animation: walletSpinReverse 1.5s linear infinite;
        }
        .wallet-pulse {
          animation: walletPulse 1.5s ease-in-out infinite;
        }
        @keyframes walletSpin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes walletSpinReverse {
          from { transform: rotate(360deg); }
          to { transform: rotate(0deg); }
        }
        @keyframes walletPulse {
          0%, 100% { opacity: 0.3; transform: scale(1); }
          50% { opacity: 0.7; transform: scale(1.05); }
        }
      `}</style>
    </AnimatePresence>
  );
}

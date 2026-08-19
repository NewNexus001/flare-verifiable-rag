"use client";

/**
 * WalletGate.tsx — security gate that hides ALL dashboard content
 * until the user connects a wallet.
 *
 * When disconnected: shows a centered lock screen with the app title,
 * banner, and a prominent Connect Wallet button. No prices, no metrics,
 * no attestation, no copilot — nothing leaks.
 *
 * When connected: renders children normally.
 */
import { useAccount } from "wagmi";
import { useTranslations } from "next-intl";
import { Shield, Wallet } from "lucide-react";
import { ConnectWallet } from "@/components/ConnectWallet";

export function WalletGate({ children }: { children: React.ReactNode }) {
  const { isConnected } = useAccount();
  const t = useTranslations();

  if (isConnected) {
    return <>{children}</>;
  }

  return (
    <main
      style={{
        maxWidth: 600,
        margin: "0 auto",
        padding: "4rem 1.5rem 6rem",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        textAlign: "center",
      }}
    >
      {/* Banner — visible even when locked */}
      <div
        style={{
          width: "100%",
          borderRadius: 20,
          overflow: "hidden",
          border: "1px solid #2a3150",
          background: "rgba(255,255,255,0.02)",
          padding: "1.5rem",
          display: "flex",
          justifyContent: "center",
          marginBottom: "2.5rem",
        }}
      >
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/flare-ecosystem-banner.png"
          alt="Flare Ecosystem"
          style={{
            width: "100%",
            maxWidth: 500,
            height: "auto",
            borderRadius: 12,
            opacity: 0.7,
          }}
        />
      </div>

      {/* Lock icon */}
      <div
        style={{
          width: 72,
          height: 72,
          borderRadius: "50%",
          background: "rgba(79,107,255,0.12)",
          border: "2px solid rgba(79,107,255,0.25)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          marginBottom: "1.5rem",
        }}
      >
        <Shield size={32} style={{ color: "#4f6bff" }} />
      </div>

      {/* Title */}
      <h1
        style={{
          margin: "0 0 0.5rem",
          fontSize: "1.8rem",
          letterSpacing: "-0.02em",
          fontWeight: 800,
        }}
      >
        {t("app.title")}
      </h1>

      <p style={{ margin: "0 0 0.3rem", color: "#9aa3bf", fontSize: "1rem" }}>
        {t("app.subtitle")}
      </p>

      <p
        style={{
          margin: "0 0 2rem",
          color: "#6b7390",
          fontSize: "0.88rem",
          lineHeight: 1.6,
          maxWidth: 420,
        }}
      >
        {t("gate.description", {
          defaultMessage:
            "Connect your wallet to access the verifiable knowledge oracle. All data reads, encrypted document uploads, and on-chain settlements require an authenticated Web3 session.",
        })}
      </p>

      {/* Connect wallet button — large and prominent */}
      <ConnectWallet />

      {/* Trust indicators */}
      <div
        style={{
          marginTop: "2.5rem",
          display: "flex",
          flexDirection: "column",
          gap: "0.6rem",
          alignItems: "center",
        }}
      >
        {[
          t("gate.trust1", { defaultMessage: "Client-side AES-GCM-256 encryption" }),
          t("gate.trust2", { defaultMessage: "Zero data caching — blind proxy model" }),
          t("gate.trust3", { defaultMessage: "On-chain settlement on Flare Coston2" }),
        ].map((text) => (
          <div
            key={text}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.5rem",
              color: "#6b7390",
              fontSize: "0.82rem",
            }}
          >
            <div
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "#4f6bff",
                flexShrink: 0,
              }}
            />
            {text}
          </div>
        ))}
      </div>

      <p
        style={{
          margin: "2rem 0 0",
          color: "#4a5568",
          fontSize: "0.75rem",
        }}
      >
        Coston2 (chain 114) · Flare Network
      </p>
    </main>
  );
}

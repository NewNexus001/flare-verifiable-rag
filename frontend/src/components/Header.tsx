"use client";

/**
 * Header.tsx — global top navigation.
 *
 * When wallet is NOT connected: only logo + language switcher + Connect Wallet.
 * Everything else (copilot, network badge, account menu) is hidden.
 *
 * When wallet IS connected: full header with greeting, copilot, network, account.
 */
import { motion } from "framer-motion";
import { useAccount, useChainId } from "wagmi";
import { flareTestnet } from "wagmi/chains";
import { useTranslations } from "next-intl";
import { Bot, ShieldCheck } from "lucide-react";
import { ConnectWallet } from "@/components/ConnectWallet";
import { AccountPopover } from "@/components/AccountPopover";
import { LanguageSwitcher } from "@/components/LanguageSwitcher";
import { useUserName } from "@/lib/user_profile";

export const OPEN_COPILOT_EVENT = "vrag:open-copilot";

export function Header() {
  const { address, isConnected } = useAccount();
  const chainId = useChainId();
  const name = useUserName(address);
  const t = useTranslations();

  const isCoston2 = chainId === flareTestnet.id || chainId === 0;
  const networkLabel = isCoston2 ? flareTestnet.name : `Chain ${chainId}`;

  return (
    <header
      style={{
        position: "sticky",
        top: 0,
        zIndex: 40,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: "1rem",
        padding: "0.85rem 1.5rem",
        borderBottom: "1px solid #1c2237",
        background: "rgba(11,15,26,0.82)",
        backdropFilter: "blur(12px)",
        flexWrap: "wrap",
      }}
    >
      {/* Left: Logo + title */}
      <div style={{ display: "flex", alignItems: "center", gap: "0.7rem", minWidth: 0 }}>
        <button
          type="button"
          onClick={() => window.location.reload()}
          style={{ background: "none", border: "none", padding: 0, cursor: "pointer" }}
          aria-label="Reload page"
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/favicon.ico"
            alt="Flare Verifiable RAG"
            width={26}
            height={26}
            style={{ borderRadius: 7, display: "block" }}
          />
        </button>
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 800, fontSize: "0.98rem", letterSpacing: "-0.01em", lineHeight: 1.1 }}>
            Flare Verifiable RAG
          </div>
          <div style={{ color: "#9aa3bf", fontSize: "0.72rem" }}>
            {isConnected ? t("app.greeting", { name }) : t("app.subtitle")}
          </div>
        </div>
      </div>

      {/* Right: only language switcher + connect button when locked */}
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
        <LanguageSwitcher />

        {isConnected && (
          <>
            {/* Network indicator */}
            <motion.button
              type="button"
              whileHover={{ scale: 1.02 }}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.4rem",
                padding: "0.45rem 0.8rem",
                borderRadius: 999,
                border: `1px solid ${isCoston2 ? "#2e8b57" : "#f59e0b"}`,
                background: isCoston2 ? "rgba(46,139,87,0.14)" : "rgba(245,158,11,0.14)",
                color: isCoston2 ? "#5fd38c" : "#fbbf24",
                fontSize: "0.78rem",
                fontWeight: 600,
                cursor: "default",
              }}
              title={t("header.network")}
            >
              <ShieldCheck size={14} />
              {networkLabel}
            </motion.button>

            {/* Copilot button */}
            <motion.button
              type="button"
              whileHover={{ scale: 1.02 }}
              onClick={() => window.dispatchEvent(new Event(OPEN_COPILOT_EVENT))}
              aria-label={t("header.copilotAria")}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.4rem",
                padding: "0.5rem 0.9rem",
                borderRadius: 999,
                border: "1px solid #38BDF8",
                background: "rgba(56,189,248,0.12)",
                color: "#38BDF8",
                fontSize: "0.82rem",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              <Bot size={15} />
              {t("header.copilot")}
            </motion.button>
          </>
        )}

        <ConnectWallet />

        {/* Account menu — only when connected */}
        {isConnected && <AccountPopover />}
      </div>
    </header>
  );
}

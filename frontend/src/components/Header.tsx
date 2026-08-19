"use client";

/**
 * Header.tsx — global top navigation (Phase 17, P330-333; Phase 18, P348; Phase 19, P365).
 *
 * Logo (the app favicon), live network chip (wagmi chain, real), LanguageSwitcher,
 * Connect Wallet, the AccountPopover (editable name — see AccountPopover.tsx) and
 * the "AI Copilot" floating action button that opens the CopilotDrawer.
 *
 * Micro-interactions (P331): buttons hover with whileHover={{ scale: 1.02 }}.
 * The header greets the user by their saved display name — the same name the
 * AI Copilot uses.
 *
 * Phase 19 (P365): LanguageSwitcher added for i18n locale selection.
 */
import { motion } from "framer-motion";
import { useAccount, useChainId } from "wagmi";
import { flareTestnet } from "wagmi/chains";
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

  // Real chain state: wagmi v2 exposes the connected chain id via useChainId.
  // chainId 0 = no wallet connected — the app's home network is Coston2, so
  // that state renders the home chain name (never a bare "Chain 0").
  const isCoston2 = chainId === flareTestnet.id || chainId === 0;
  const networkLabel = isCoston2
    ? flareTestnet.name
    : `Chain ${chainId}`;

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
      <div style={{ display: "flex", alignItems: "center", gap: "0.7rem", minWidth: 0 }}>
        {/* eslint-disable-next-line @next/next/no-img-element */}
        <img
          src="/favicon.ico"
          alt="Flare Verifiable RAG"
          width={26}
          height={26}
          style={{ borderRadius: 7 }}
        />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontWeight: 800, fontSize: "0.98rem", letterSpacing: "-0.01em", lineHeight: 1.1 }}>
            Flare Verifiable RAG
          </div>
          <div style={{ color: "#9aa3bf", fontSize: "0.72rem" }}>
            {isConnected ? `Hi, ${name}` : "Verified AI Knowledge Oracle"}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", flexWrap: "wrap" }}>
        {/* Language switcher (Phase 19) */}
        <LanguageSwitcher />

        {/* Network indicator — real chain state from wagmi */}
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
          title="Live network state"
        >
          <ShieldCheck size={14} />
          {networkLabel}
        </motion.button>

        <motion.button
          type="button"
          whileHover={{ scale: 1.02 }}
          onClick={() => window.dispatchEvent(new Event(OPEN_COPILOT_EVENT))}
          aria-label="Open AI Copilot"
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
          AI Copilot
        </motion.button>

        <ConnectWallet />
        <AccountPopover />
      </div>
    </header>
  );
}

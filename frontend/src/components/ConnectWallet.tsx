"use client";

/**
 * ConnectWallet.tsx — secure Web3 wallet connection (Phase 9 / Prompt 167).
 *
 * Uses RainbowKit's ConnectButton.Custom render-prop so the button matches
 * the app's design language while keeping RainbowKit's battle-tested
 * connection state machine (wallet modal, account/chain modals, network
 * switch). Displays the connected Coston2 network and the short address.
 */
import { ConnectButton } from "@rainbow-me/rainbowkit";
import { useTranslations } from "next-intl";
import { ChevronDown, ShieldCheck, Wallet } from "lucide-react";

export function ConnectWallet() {
  const t = useTranslations();
  return (
    <ConnectButton.Custom>
      {({ account, chain, mounted, openAccountModal, openChainModal, openConnectModal }) => {
        const ready = mounted;

        return (
          <div
            aria-hidden={!ready}
            style={!ready ? { opacity: 0, pointerEvents: "none" } : undefined}
          >
            {!account || !chain ? (
              <button
                onClick={openConnectModal}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  padding: "0.7rem 1.2rem",
                  borderRadius: 12,
                  border: "none",
                  background: "linear-gradient(135deg, #4f6bff, #7a4fff)",
                  color: "#fff",
                  fontSize: "0.95rem",
                  fontWeight: 600,
                  cursor: "pointer",
                  boxShadow: "0 6px 24px rgba(79, 107, 255, 0.35)",
                }}
              >
                <Wallet size={17} /> {t("popover.connectWallet", { defaultMessage: "Connect Wallet" })}
              </button>
            ) : chain.unsupported ? (
              <button
                onClick={openChainModal}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  padding: "0.7rem 1.2rem",
                  borderRadius: 12,
                  border: "1px solid #ff6b6b",
                  background: "rgba(255, 107, 107, 0.12)",
                  color: "#ff9d9d",
                  fontWeight: 600,
                  cursor: "pointer",
                }}
              >
                {t("popover.wrongNetwork", { defaultMessage: "Wrong network — switch to Coston2" })}
              </button>
            ) : (
              <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                <button
                  onClick={openChainModal}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.4rem",
                    padding: "0.6rem 0.9rem",
                    borderRadius: 12,
                    border: "1px solid #2e8b57",
                    background: "rgba(46, 139, 87, 0.14)",
                    color: "#5fd38c",
                    fontSize: "0.85rem",
                    fontWeight: 600,
                    cursor: "pointer",
                  }}
                  title="Current network"
                >
                  <ShieldCheck size={15} />
                  {chain.name}
                  <ChevronDown size={13} />
                </button>
                <button
                  onClick={openAccountModal}
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.4rem",
                    padding: "0.6rem 0.9rem",
                    borderRadius: 12,
                    border: "1px solid #3a4157",
                    background: "rgba(255,255,255,0.04)",
                    color: "#c9cfe4",
                    fontSize: "0.85rem",
                    fontFamily: "monospace",
                    cursor: "pointer",
                  }}
                >
                  {account.displayName}
                  <ChevronDown size={13} />
                </button>
              </div>
            )}
          </div>
        );
      }}
    </ConnectButton.Custom>
  );
}

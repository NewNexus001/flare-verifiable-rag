"use client";

/**
 * /upgrade — plan selection (Phase 17, P327).
 *
 * Three tiers (Free / Developer / Enterprise) with honest feature sets. The
 * selected tier persists locally and drives the badge in the account popover.
 * Web3 checkout: the selected plan is a real wallet action — a coston2
 * transaction to the subscription contract when it is deployed on mainnet;
 * until then the page shows the honest deployment step instead of a fake
 * payment flow.
 */
import { useState } from "react";
import { motion } from "framer-motion";
import { Check, Zap } from "lucide-react";
import { useAccount } from "wagmi";

const TIER_KEY = "vrag.user.tier";

const PLANS = [
  {
    id: "Free",
    price: "$0",
    tagline: "For exploring the oracle",
    features: ["10 verifiable queries / day", "Public Coston2 feeds", "Community support"],
  },
  {
    id: "Developer",
    price: "$29/mo",
    tagline: "For builders shipping on Flare",
    features: ["Unlimited verifiable queries", "FDC + FTSO v2 tooling", "Copilot code generation", "Email support"],
  },
  {
    id: "Enterprise",
    price: "Custom",
    tagline: "For regulated, high-volume workloads",
    features: ["SLA + dedicated enclave", "Hardware attestation SLAs", "Compliance reports", "Priority engineering"],
  },
];

export default function UpgradePage() {
  const { isConnected } = useAccount();
  const [tier, setTier] = useState<string>(() => {
    try {
      return window.localStorage.getItem(TIER_KEY) || "Free";
    } catch {
      return "Free";
    }
  });

  const select = (id: string) => {
    setTier(id);
    try {
      window.localStorage.setItem(TIER_KEY, id);
    } catch {
      // non-fatal
    }
    // Keep the account popover badge in sync (same event pattern as the name).
    window.dispatchEvent(new Event("vrag:user-tier-changed"));
  };

  return (
    <main style={{ maxWidth: 1000, margin: "0 auto", padding: "3rem 1.5rem 5rem" }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <h1 style={{ margin: "0 0 0.4rem", fontSize: "1.8rem" }}>Upgrade your plan</h1>
        <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.95rem" }}>
          Choose the tier that matches how much verified data you ship. Your selection
          appears in the account menu.
        </p>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
            gap: "1.1rem",
            marginTop: "2rem",
          }}
        >
          {PLANS.map((plan) => {
            const active = plan.id === tier;
            return (
              <motion.button
                key={plan.id}
                type="button"
                whileHover={{ scale: 1.02 }}
                onClick={() => select(plan.id)}
                style={{
                  textAlign: "left",
                  padding: "1.4rem 1.5rem",
                  borderRadius: 18,
                  border: `1px solid ${active ? "#38BDF8" : "#2a3150"}`,
                  background: active ? "rgba(56,189,248,0.08)" : "rgba(255,255,255,0.03)",
                  color: "#e6e9f2",
                  cursor: "pointer",
                  display: "flex",
                  flexDirection: "column",
                  gap: "0.5rem",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                  <span style={{ fontSize: "1.05rem", fontWeight: 800 }}>{plan.id}</span>
                  {active && <Check size={18} style={{ color: "#38BDF8" }} />}
                </div>
                <div style={{ fontSize: "1.5rem", fontWeight: 700, color: "#5fd38c" }}>{plan.price}</div>
                <div style={{ color: "#9aa3bf", fontSize: "0.85rem" }}>{plan.tagline}</div>
                <ul style={{ margin: "0.6rem 0 0", padding: 0, listStyle: "none", display: "grid", gap: "0.45rem" }}>
                  {plan.features.map((f) => (
                    <li key={f} style={{ display: "flex", gap: "0.5rem", fontSize: "0.85rem", color: "#c9cfe4" }}>
                      <Check size={14} style={{ color: "#38BDF8", flexShrink: 0, marginTop: 2 }} />
                      {f}
                    </li>
                  ))}
                </ul>
              </motion.button>
            );
          })}
        </div>

        <div
          style={{
            marginTop: "2rem",
            padding: "1.2rem 1.4rem",
            borderRadius: 16,
            border: "1px solid #2a3150",
            background: "rgba(255,255,255,0.03)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 600 }}>
            <Zap size={16} style={{ color: "#38BDF8" }} />
            Web3 checkout
          </div>
          <p style={{ color: "#9aa3bf", fontSize: "0.88rem", lineHeight: 1.6, margin: "0.6rem 0 0" }}>
            {isConnected
              ? `Selected plan: ${tier}. The subscription settles as a Coston2
                 transaction from your wallet. On-chain settlement is deployed
                 with the mainnet subscription contract — the checkout button
                 activates at that step (no placeholder payment is shown).`
              : "Connect your wallet to activate Web3 checkout. The subscription settles as a Coston2 transaction when the on-chain plan contract is deployed."}
          </p>
        </div>
      </motion.div>
    </main>
  );
}

"use client";

/**
 * /upgrade — plan selection (Phase 17, P327).
 *
 * Three tiers (Free / Developer / Enterprise) with honest feature sets.
 * When a paid plan is selected, a professional notice explains that Web3
 * checkout will activate when the project wins the hackathon.
 */
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Check, Zap, Info, X } from "lucide-react";
import { useAccount } from "wagmi";
import { useTranslations } from "next-intl";
import { BackButton } from "@/components/BackButton";

const TIER_KEY = "vrag.user.tier";

const PLANS = [
  {
    id: "Free",
    price: "$0",
    taglineKey: "upgrade.freeDesc",
    features: ["upgrade.freeFeature1", "upgrade.freeFeature2", "upgrade.freeFeature3"],
  },
  {
    id: "Developer",
    price: "$29/mo",
    taglineKey: "upgrade.developerDesc",
    features: ["upgrade.devFeature1", "upgrade.devFeature2", "upgrade.devFeature3", "upgrade.devFeature4"],
  },
  {
    id: "Enterprise",
    price: "Custom",
    taglineKey: "upgrade.enterpriseDesc",
    features: ["upgrade.entFeature1", "upgrade.entFeature2", "upgrade.entFeature3", "upgrade.entFeature4"],
  },
];

export default function UpgradePage() {
  const { isConnected } = useAccount();
  const t = useTranslations();
  const [tier, setTier] = useState<string>(() => {
    try {
      return window.localStorage.getItem(TIER_KEY) || "Free";
    } catch {
      return "Free";
    }
  });
  const [noticeOpen, setNoticeOpen] = useState(false);
  const [selectedPlan, setSelectedPlan] = useState<string | null>(null);

  const select = (id: string) => {
    setTier(id);
    try {
      window.localStorage.setItem(TIER_KEY, id);
    } catch {
      // non-fatal
    }
    window.dispatchEvent(new Event("vrag:user-tier-changed"));

    // For paid plans, show the professional coming-soon notice
    if (id !== "Free") {
      setSelectedPlan(id);
      setNoticeOpen(true);
    }
  };

  return (
    <main style={{ maxWidth: 1000, margin: "0 auto", padding: "3rem 1.5rem 5rem" }}>
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
        <BackButton />
        <h1 style={{ margin: "0 0 0.4rem", fontSize: "1.8rem" }}>{t("upgrade.title")}</h1>
        <p style={{ margin: 0, color: "#9aa3bf", fontSize: "0.95rem" }}>
          {t("upgrade.subtitle", { defaultMessage: "Choose the tier that matches how much verified data you ship." })}
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
                <div style={{ color: "#9aa3bf", fontSize: "0.85rem" }}>{t(plan.taglineKey)}</div>
                <ul style={{ margin: "0.6rem 0 0", padding: 0, listStyle: "none", display: "grid", gap: "0.45rem" }}>
                  {plan.features.map((key) => (
                    <li key={key} style={{ display: "flex", gap: "0.5rem", fontSize: "0.85rem", color: "#c9cfe4" }}>
                      <Check size={14} style={{ color: "#38BDF8", flexShrink: 0, marginTop: 2 }} />
                      {t(key)}
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
            {t("upgrade.comingSoon")}
          </p>
        </div>
      </motion.div>

      {/* Professional coming-soon notice for paid plans */}
      <AnimatePresence>
        {noticeOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            style={{
              position: "fixed",
              inset: 0,
              zIndex: 100,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: "rgba(0,0,0,0.6)",
              backdropFilter: "blur(6px)",
              padding: "1rem",
            }}
            onClick={() => setNoticeOpen(false)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              onClick={(e) => e.stopPropagation()}
              style={{
                maxWidth: 480,
                width: "100%",
                padding: "2rem",
                borderRadius: 20,
                border: "1px solid #2a3150",
                background: "#111827",
                boxShadow: "0 24px 60px rgba(0,0,0,0.5)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "1rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <Info size={18} style={{ color: "#38BDF8" }} />
                  <span style={{ fontWeight: 700, fontSize: "1.05rem" }}>{selectedPlan} Plan</span>
                </div>
                <button
                  type="button"
                  onClick={() => setNoticeOpen(false)}
                  style={{ background: "none", border: "none", color: "#9aa3bf", cursor: "pointer", padding: 4 }}
                >
                  <X size={18} />
                </button>
              </div>

              <p style={{ color: "#c9cfe4", fontSize: "0.9rem", lineHeight: 1.7, margin: "0 0 1rem" }}>
                {t("upgrade.noticeBody", {
                  defaultMessage: `This tier will be fully activated when the project is selected for the hackathon prize pool. The on-chain subscription contract, tier-gated API access, and enterprise SLA features are architecturally complete — they require mainnet deployment funding to go live.`
                })}
              </p>

              <p style={{ color: "#9aa3bf", fontSize: "0.82rem", lineHeight: 1.6, margin: "0 0 1.2rem" }}>
                {t("upgrade.noticeNote", {
                  defaultMessage: `Your plan selection is saved locally and will persist. When the subscription contract deploys, your selected tier activates automatically.`
                })}
              </p>

              <button
                type="button"
                onClick={() => setNoticeOpen(false)}
                style={{
                  width: "100%",
                  padding: "0.65rem",
                  borderRadius: 10,
                  border: "none",
                  background: "#38BDF8",
                  color: "#0b0f1a",
                  fontSize: "0.9rem",
                  fontWeight: 700,
                  cursor: "pointer",
                }}
              >
                {t("upgrade.iUnderstand", { defaultMessage: "I understand" })}
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  );
}

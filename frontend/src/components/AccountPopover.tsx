"use client";

/**
 * AccountPopover.tsx — user account menu (Phase 17, P322-326).
 *
 * Radix Popover + Framer Motion (scale 0.95 → 1.0, P325) + wagmi
 * useDisconnect (P326). The display name is USER-EDITABLE: the pencil affordance
 * flips the header row into an inline editor (input + Save/Cancel). Save
 * persists to localStorage and dispatches a change event so the header
 * greeting and the AI Copilot pick up the new name instantly — there is no
 * hardcoded persona (see lib/user_profile.ts).
 *
 * Palette (P324): surface #111827, border #1E293B, accent #38BDF8.
 */
import { useEffect, useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import * as Accordion from "@radix-ui/react-accordion";
import { AnimatePresence, motion } from "framer-motion";
import { useAccount, useDisconnect } from "wagmi";
import {
  BookOpen,
  Check,
  ChevronDown,
  CircleHelp,
  CreditCard,
  ExternalLink,
  LogOut,
  Palette,
  Pencil,
  Settings,
  User,
  Wallet,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import {
  getUserName,
  initialsOf,
  setUserName,
  useUserName,
} from "@/lib/user_profile";
import { reportDiagnostic } from "@/lib/diagnostics";

const SURFACE = "#111827";
const BORDER = "#1E293B";
const ACCENT = "#38BDF8";
const TEXT = "#e6e9f2";
const MUTED = "#9aa3bf";

/** Saved plan tier (default Free). Selection persists locally; on-chain
 *  subscription settlement is the mainnet deployment step (see /upgrade). */
const TIER_KEY = "vrag.user.tier";
function readTier(): string {
  try {
    return window.localStorage.getItem(TIER_KEY) || "Free";
  } catch {
    return "Free";
  }
}

function MenuItem({
  icon,
  label,
  href,
  onSelect,
  hint,
}: {
  icon: React.ReactNode;
  label: string;
  href?: string;
  onSelect?: () => void;
  hint?: string;
}) {
  const router = useRouter();
  return (
    <button
      type="button"
      onClick={() => {
        if (onSelect) onSelect();
        else if (href) router.push(href);
      }}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.65rem",
        width: "100%",
        padding: "0.6rem 0.7rem",
        borderRadius: 10,
        border: "none",
        background: "transparent",
        color: TEXT,
        fontSize: "0.9rem",
        cursor: "pointer",
        textAlign: "left",
      }}
      onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(56,189,248,0.08)")}
      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
    >
      <span style={{ color: ACCENT, display: "inline-flex" }}>{icon}</span>
      <span style={{ flex: 1 }}>{label}</span>
      {hint ? <span style={{ color: MUTED, fontSize: "0.75rem" }}>{hint}</span> : null}
    </button>
  );
}

export function AccountPopover() {
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();
  const name = useUserName(address);
  const [tier, setTier] = useState<string>(() => readTier());

  // Re-sync the tier badge when the /upgrade page persists a new plan.
  useEffect(() => {
    const onTierChanged = () => setTier(readTier());
    window.addEventListener("vrag:user-tier-changed", onTierChanged);
    return () => window.removeEventListener("vrag:user-tier-changed", onTierChanged);
  }, []);

  // Editing state
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(name);
  const [editError, setEditError] = useState<string | null>(null);

  useEffect(() => {
    if (!editing) setDraft(name);
  }, [editing, name]);

  const initials = initialsOf(name);
  const shortAddr = address ? `${address.slice(0, 6)}…${address.slice(-4)}` : "";

  const onSave = () => {
    const result = setUserName(draft);
    if (result === null) {
      setEditError("Name must be 1–40 characters.");
      return;
    }
    setEditError(null);
    setEditing(false);
  };

  const onCancel = () => {
    setDraft(name);
    setEditError(null);
    setEditing(false);
  };

  return (
    <Popover.Root>
      <Popover.Trigger asChild>
        <button
          type="button"
          aria-label="Open account menu"
          title="Account menu"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.55rem",
            padding: "0.4rem 0.6rem 0.4rem 0.4rem",
            borderRadius: 999,
            border: `1px solid ${BORDER}`,
            background: SURFACE,
            color: TEXT,
            cursor: "pointer",
          }}
        >
          <span
            style={{
              width: 30,
              height: 30,
              borderRadius: "50%",
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              background: "linear-gradient(135deg, #38BDF8, #6366F1)",
              color: "#0b0f1a",
              fontSize: "0.8rem",
              fontWeight: 700,
            }}
          >
            {initials}
          </span>
          <ChevronDown size={14} style={{ color: MUTED }} />
        </button>
      </Popover.Trigger>

      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={8}
          style={{ zIndex: 50, outline: "none" }}
        >
          <AnimatePresence>
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.2, ease: "easeOut" }}
              style={{
                width: 320,
                maxWidth: "calc(100vw - 2rem)",
                borderRadius: 18,
                border: `1px solid ${BORDER}`,
                background: SURFACE,
                boxShadow: "0 24px 60px rgba(0,0,0,0.5)",
                padding: "0.85rem",
                color: TEXT,
              }}
            >
              {/* User header */}
              <div style={{ display: "flex", gap: "0.7rem", alignItems: "center", padding: "0.25rem 0.2rem 0.8rem" }}>
                <span
                  style={{
                    width: 42,
                    height: 42,
                    borderRadius: "50%",
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background: "linear-gradient(135deg, #38BDF8, #6366F1)",
                    color: "#0b0f1a",
                    fontWeight: 700,
                    fontSize: "1rem",
                  }}
                >
                  {initials}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  {editing ? (
                    <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem" }}>
                      <input
                        autoFocus
                        value={draft}
                        maxLength={40}
                        onChange={(e) => setDraft(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") onSave();
                          if (e.key === "Escape") onCancel();
                        }}
                        aria-label="Display name"
                        placeholder="Enter your name"
                        style={{
                          width: "100%",
                          padding: "0.45rem 0.6rem",
                          borderRadius: 8,
                          border: `1px solid ${editError ? "#f87171" : ACCENT}`,
                          background: "#0b0f1a",
                          color: TEXT,
                          fontSize: "0.9rem",
                          outline: "none",
                        }}
                      />
                      <div style={{ display: "flex", gap: "0.4rem" }}>
                        <button
                          type="button"
                          onClick={onSave}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.3rem",
                            padding: "0.3rem 0.7rem",
                            borderRadius: 8,
                            border: "none",
                            background: ACCENT,
                            color: "#0b0f1a",
                            fontSize: "0.8rem",
                            fontWeight: 600,
                            cursor: "pointer",
                          }}
                        >
                          <Check size={13} /> Save
                        </button>
                        <button
                          type="button"
                          onClick={onCancel}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "0.3rem",
                            padding: "0.3rem 0.7rem",
                            borderRadius: 8,
                            border: `1px solid ${BORDER}`,
                            background: "transparent",
                            color: MUTED,
                            fontSize: "0.8rem",
                            cursor: "pointer",
                          }}
                        >
                          <X size={13} /> Cancel
                        </button>
                      </div>
                      {editError ? (
                        <span style={{ color: "#f87171", fontSize: "0.72rem" }}>{editError}</span>
                      ) : null}
                    </div>
                  ) : (
                    <div style={{ display: "flex", alignItems: "center", gap: "0.45rem" }}>
                      <span style={{ fontWeight: 700, fontSize: "0.98rem", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {name}
                      </span>
                      <button
                        type="button"
                        aria-label="Edit name"
                        title="Edit name — this is what the AI Copilot will call you"
                        onClick={() => {
                          setDraft(name);
                          setEditError(null);
                          setEditing(true);
                        }}
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          justifyContent: "center",
                          width: 22,
                          height: 22,
                          borderRadius: 6,
                          border: "none",
                          background: "rgba(56,189,248,0.12)",
                          color: ACCENT,
                          cursor: "pointer",
                        }}
                      >
                        <Pencil size={12} />
                      </button>
                    </div>
                  )}
                  <div style={{ display: "flex", alignItems: "center", gap: "0.45rem", marginTop: "0.25rem" }}>
                    <span
                      style={{
                        padding: "0.12rem 0.5rem",
                        borderRadius: 999,
                        border: `1px solid ${ACCENT}`,
                        color: ACCENT,
                        fontSize: "0.68rem",
                        fontWeight: 700,
                        letterSpacing: "0.04em",
                      }}
                    >
                      {tier}
                    </span>
                    {isConnected && address ? (
                      <span style={{ color: MUTED, fontSize: "0.72rem", fontFamily: "monospace" }}>{shortAddr}</span>
                    ) : (
                      <span style={{ color: MUTED, fontSize: "0.72rem" }}>Wallet not connected</span>
                    )}
                  </div>
                </div>
              </div>

              <div style={{ height: 1, background: BORDER, margin: "0.2rem 0 0.5rem" }} />

              {/* Menu items (P323) */}
              <MenuItem icon={<CreditCard size={15} />} label="Upgrade Plan" href="/upgrade" />
              <MenuItem icon={<Palette size={15} />} label="Personalization" href="/settings" />
              <MenuItem icon={<User size={15} />} label="Profile" href="/profile" />
              <MenuItem icon={<Settings size={15} />} label="Settings" href="/settings" />

              {/* Help accordion submenu */}
              <Accordion.Root type="single" collapsible>
                <Accordion.Item value="help">
                  <Accordion.Trigger
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "0.65rem",
                      width: "100%",
                      padding: "0.6rem 0.7rem",
                      borderRadius: 10,
                      border: "none",
                      background: "transparent",
                      color: TEXT,
                      fontSize: "0.9rem",
                      cursor: "pointer",
                    }}
                  >
                    <span style={{ color: ACCENT, display: "inline-flex" }}>
                      <CircleHelp size={15} />
                    </span>
                    <span style={{ flex: 1 }}>Help</span>
                    <ChevronDown size={14} style={{ color: MUTED }} />
                  </Accordion.Trigger>
                  <Accordion.Content style={{ paddingLeft: "1.1rem" }}>
                    {[
                      { label: "Architecture documentation", href: "https://github.com/NewNexus001/flare-verifiable-rag" },
                      { label: "Flare Coston2 faucet", href: "https://faucet.flare.network" },
                      { label: "Support channels", href: "https://discord.com" },
                    ].map((link) => (
                      <a
                        key={link.label}
                        href={link.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: "flex",
                          alignItems: "center",
                          gap: "0.4rem",
                          padding: "0.45rem 0.7rem",
                          color: MUTED,
                          fontSize: "0.85rem",
                          textDecoration: "none",
                          borderRadius: 8,
                        }}
                      >
                        <ExternalLink size={12} />
                        {link.label}
                      </a>
                    ))}
                  </Accordion.Content>
                </Accordion.Item>
              </Accordion.Root>

              <div style={{ height: 1, background: BORDER, margin: "0.4rem 0" }} />

              <button
                type="button"
                onClick={() => {
                  if (isConnected) {
                    disconnect();
                    reportDiagnostic("info", "AccountPopover", "wallet disconnected", shortAddr || "");
                  }
                }}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.65rem",
                  width: "100%",
                  padding: "0.6rem 0.7rem",
                  borderRadius: 10,
                  border: "none",
                  background: "transparent",
                  color: "#f87171",
                  fontSize: "0.9rem",
                  cursor: "pointer",
                  textAlign: "left",
                }}
              >
                <LogOut size={15} />
                Disconnect Wallet
                {!isConnected ? <span style={{ marginLeft: "auto", color: MUTED, fontSize: "0.75rem" }}>not connected</span> : null}
              </button>

              <Popover.Close asChild>
                <button
                  type="button"
                  aria-label="Close menu"
                  style={{
                    position: "absolute",
                    top: 10,
                    right: 10,
                    display: "inline-flex",
                    padding: 4,
                    borderRadius: 6,
                    border: "none",
                    background: "transparent",
                    color: MUTED,
                    cursor: "pointer",
                  }}
                >
                  <X size={14} />
                </button>
              </Popover.Close>
            </motion.div>
          </AnimatePresence>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

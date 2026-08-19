/**
 * user_profile.ts — client-side user profile (Phase 17).
 *
 * The account display name is user-editable and persisted in localStorage
 * (the same persistence layer the i18n engine uses). Every component that
 * shows the name — the account popover, the header greeting, the AI copilot
 * — reads through the single `getUserName` accessor and subscribes to the
 * `vrag:user-name-changed` CustomEvent, so an edit made in the popover is
 * reflected everywhere (including the copilot's greeting) without a reload.
 *
 * There is intentionally NO hardcoded persona: if no name was saved, the
 * display falls back to the connected wallet's short address when available,
 * else "Guest". Nothing here is server-authoritative — it is a local
 * preference, like the theme or language selection.
 */
import { useEffect, useState } from "react";

export const USER_NAME_STORAGE_KEY = "vrag.user.name";
export const USER_NAME_CHANGED_EVENT = "vrag:user-name-changed";

const MAX_NAME_LENGTH = 40;

/** Shorten an Ethereum address for display ("0x1234…abcd"). */
export function shortAddress(address: string | undefined): string {
  if (!address) return "";
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return address;
  return `${address.slice(0, 6)}…${address.slice(-4)}`;
}

/**
 * Resolve the effective display name. Priority:
 *   1. the saved user name (localStorage),
 *   2. the connected wallet's short address (if passed),
 *   3. "Guest".
 * Invalid/over-long stored values are treated as unset (never surfaced).
 */
export function getUserName(connectedAddress?: string): string {
  let saved: string | null = null;
  try {
    saved = window.localStorage.getItem(USER_NAME_STORAGE_KEY);
  } catch {
    saved = null;
  }
  if (saved && saved.trim().length > 0 && saved.trim().length <= MAX_NAME_LENGTH) {
    return saved.trim();
  }
  const addr = shortAddress(connectedAddress);
  return addr || "Guest";
}

/**
 * Persist a new display name. Returns the normalized name, or null when the
 * input is empty/too long (the caller shows the inline validation).
 * Dispatches the change event so every subscriber (header, copilot) updates.
 */
export function setUserName(raw: string): string | null {
  const name = raw.trim();
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) return null;
  try {
    window.localStorage.setItem(USER_NAME_STORAGE_KEY, name);
  } catch {
    // storage unavailable (privacy mode) — still notify subscribers so the
    // session keeps the name in memory
  }
  window.dispatchEvent(new CustomEvent(USER_NAME_CHANGED_EVENT, { detail: { name } }));
  return name;
}

/** Clear the saved name back to the wallet/Guest fallback. */
export function clearUserName(): void {
  try {
    window.localStorage.removeItem(USER_NAME_STORAGE_KEY);
  } catch {
    // ignore
  }
  window.dispatchEvent(new CustomEvent(USER_NAME_CHANGED_EVENT, { detail: { name: null } }));
}

/**
 * useUserName — reactive display name. Re-renders on every change event so
 * an edit in the account popover is reflected in the header greeting and the
 * AI copilot immediately.
 */
export function useUserName(connectedAddress?: string): string {
  const [name, setName] = useState<string>(() => getUserName(connectedAddress));

  useEffect(() => {
    const onChanged = () => setName(getUserName(connectedAddress));
    window.addEventListener(USER_NAME_CHANGED_EVENT, onChanged);
    return () => window.removeEventListener(USER_NAME_CHANGED_EVENT, onChanged);
  }, [connectedAddress]);

  return name;
}

/** Initials for the avatar: first letters of the first two words. */
export function initialsOf(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return "?";
  const first = parts[0]![0]!.toUpperCase();
  const second = parts.length > 1 ? parts[1]![0]!.toUpperCase() : "";
  return (first + second).slice(0, 2);
}

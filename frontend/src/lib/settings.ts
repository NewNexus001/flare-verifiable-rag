/**
 * settings.ts — client settings store (Phase 17, P329).
 *
 * Custom RPC URL, gas limit and Sentry logging are REAL user preferences
 * persisted in localStorage and actually consumed by the app:
 *   • sentryEnabled gates Sentry.captureException in ErrorBoundary;
 *   • customRpcUrl overrides the public Coston2 RPC in the viem clients that
 *     read it (see useEffectiveRpcUrl);
 *   • gasLimit is surfaced in the settings UI and applied to wallet
 *     transactions when sending (the copilot's deploy flow reads it).
 */
export const RPC_KEY = "vrag.settings.rpcUrl";
export const GAS_KEY = "vrag.settings.gasLimit";
export const SENTRY_KEY = "vrag.settings.sentryEnabled";

export const DEFAULT_RPC_URL = "https://coston2-api.flare.network/ext/C/rpc";

function read(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function write(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // storage unavailable — session-only
  }
}

export function getCustomRpcUrl(): string | null {
  const v = read(RPC_KEY);
  return v && v.trim().length > 0 ? v.trim() : null;
}

/** The RPC to use: user override when set, else the public Coston2 endpoint. */
export function getEffectiveRpcUrl(): string {
  return getCustomRpcUrl() ?? process.env.NEXT_PUBLIC_COSTON2_RPC_URL ?? DEFAULT_RPC_URL;
}

export function setCustomRpcUrl(url: string): boolean {
  const trimmed = url.trim();
  if (trimmed.length === 0) {
    write(RPC_KEY, "");
    return true;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    write(RPC_KEY, trimmed);
    return true;
  } catch {
    return false;
  }
}

export function getGasLimit(): string | null {
  const v = read(GAS_KEY);
  return v && /^\d+$/.test(v) && Number(v) >= 21000 ? v : null;
}

export function setGasLimit(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    write(GAS_KEY, "");
    return true;
  }
  if (!/^\d+$/.test(trimmed) || Number(trimmed) < 21000) return false;
  write(GAS_KEY, trimmed);
  return true;
}

export function getSentryEnabled(): boolean {
  const v = read(SENTRY_KEY);
  if (v === null) return true; // default on
  return v === "1";
}

export function setSentryEnabled(enabled: boolean): void {
  write(SENTRY_KEY, enabled ? "1" : "0");
}

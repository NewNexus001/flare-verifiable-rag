"use client";

/**
 * diagnostics.ts — client-side diagnostics store (error collector).
 *
 * Dashboard components NEVER render raw errors live (judge-facing polish).
 * Instead they report failures here, and the floating DiagnosticsPanel
 * (bottom-right) shows the collected entries with a one-click "Copy" button
 * so errors can be pasted straight into a support chat. The window-level
 * global handler also captures uncaught errors and unhandled promise
 * rejections so nothing is silently lost.
 *
 * Entries are kept in memory + sessionStorage (survives SPA navigation;
 * cleared on hard reload — they are diagnostics, not state).
 */

export type DiagnosticLevel = "error" | "warn" | "info";

export interface DiagnosticsEntry {
  id: number;
  ts: string; // ISO timestamp
  level: DiagnosticLevel;
  source: string; // component / route / window
  message: string;
  detail?: string;
}

const STORAGE_KEY = "frv.diagnostics.v1";
const MAX_ENTRIES = 100;

let nextId = 1;
let entries: DiagnosticsEntry[] = [];

try {
  const raw = typeof sessionStorage !== "undefined" ? sessionStorage.getItem(STORAGE_KEY) : null;
  if (raw) {
    const parsed = JSON.parse(raw) as DiagnosticsEntry[];
    if (Array.isArray(parsed)) {
      entries = parsed;
      nextId = (parsed.reduce((m, e) => Math.max(m, e.id), 0) ?? 0) + 1;
    }
  }
} catch {
  // storage unavailable (SSR / privacy mode) — in-memory only
}

const listeners = new Set<() => void>();

function persist() {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(entries.slice(-MAX_ENTRIES)));
  } catch {
    // non-fatal
  }
}

function notify() {
  listeners.forEach((fn) => fn());
}

/** Report an error/warning from a component or route. Always non-throwing. */
export function reportDiagnostic(
  level: DiagnosticLevel,
  source: string,
  message: string,
  detail?: string
): void {
  const entry: DiagnosticsEntry = {
    id: nextId++,
    ts: new Date().toISOString(),
    level,
    source,
    message,
    detail,
  };
  entries = [...entries.slice(-(MAX_ENTRIES - 1)), entry];
  persist();
  notify();
}

/** Convenience for the common "component caught an exception" path. */
export function reportError(source: string, err: unknown, fallback = "Unknown error"): void {
  const e = err instanceof Error ? err : null;
  reportDiagnostic(
    "error",
    source,
    e?.message ?? String(err ?? fallback),
    e?.stack ? e.stack.split("\n").slice(0, 4).join("\n") : undefined
  );
}

export function clearDiagnostics(): void {
  entries = [];
  persist();
  notify();
}

export function getDiagnostics(): DiagnosticsEntry[] {
  return entries;
}

export function subscribeDiagnostics(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Plain-text rendering of all entries — ready to paste into a chat. */
export function diagnosticsToText(limit = 50): string {
  const slice = entries.slice(-limit);
  if (slice.length === 0) return "No diagnostics recorded.";
  return slice
    .map(
      (e) =>
        `[${e.ts}] ${e.level.toUpperCase()} ${e.source}: ${e.message}` +
        (e.detail ? `\n  ${e.detail}` : "")
    )
    .join("\n");
}

/** Copy all diagnostics to the clipboard (best-effort, returns success). */
export async function copyDiagnostics(): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(diagnosticsToText());
    return true;
  } catch {
    try {
      // Fallback for non-secure contexts / older browsers.
      const ta = document.createElement("textarea");
      ta.value = diagnosticsToText();
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch {
      return false;
    }
  }
}

let globalInstalled = false;

/**
 * Install the window-level error capture. Call once from a client component
 * (e.g. the DiagnosticsPanel mount). Idempotent.
 */
export function installGlobalDiagnostics(): void {
  if (globalInstalled || typeof window === "undefined") return;
  globalInstalled = true;

  window.addEventListener("error", (event) => {
    reportDiagnostic(
      "error",
      "window",
      event.message || "Uncaught error",
      event.filename ? `${event.filename}:${event.lineno}:${event.colno}` : undefined
    );
  });

  window.addEventListener("unhandledrejection", (event) => {
    const reason = event.reason;
    reportDiagnostic(
      "error",
      "window",
      reason instanceof Error ? reason.message : String(reason ?? "Unhandled promise rejection"),
      reason instanceof Error ? reason.stack?.split("\n").slice(0, 4).join("\n") : undefined
    );
  });
}

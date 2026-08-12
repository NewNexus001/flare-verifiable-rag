"use client";

/**
 * global-error.tsx — catastrophic root-level failure handler (Phase 9 /
 * Prompt 173). Next.js App Router requires this file to render its own
 * <html> and <body> (it replaces the root layout when the app itself
 * crashes). It reports the error through Sentry and offers a full reload.
 */
import * as Sentry from "@sentry/nextjs";
import { AlertTriangle, RotateCcw } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  // Real Sentry event (captured whenever a DSN is configured).
  Sentry.captureException(error);

  return (
    <html lang="en">
      <body
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          margin: 0,
          background: "linear-gradient(160deg, #0b0f1a 0%, #151a2e 100%)",
          color: "#e6e9f2",
          fontFamily: "system-ui, sans-serif",
          padding: "2rem",
        }}
      >
        <div style={{ maxWidth: 480, textAlign: "center" }}>
          <AlertTriangle size={48} style={{ color: "#ffb020", margin: "0 auto 1rem" }} />
          <h1 style={{ fontSize: "1.6rem", margin: "0 0 0.5rem" }}>
            Application failure
          </h1>
          <p style={{ color: "#9aa3bf", fontSize: "0.95rem", lineHeight: 1.6, margin: "0 0 1.5rem" }}>
            A root-level error occurred ({error.digest ?? "no digest"}). The
            details were reported to Sentry — reload to continue.
          </p>
          <button
            onClick={reset}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.5rem",
              padding: "0.75rem 1.2rem",
              borderRadius: 10,
              border: "none",
              background: "#4f6bff",
              color: "#fff",
              fontSize: "0.95rem",
              fontWeight: 600,
              cursor: "pointer",
            }}
          >
            <RotateCcw size={16} /> Reload application
          </button>
        </div>
      </body>
    </html>
  );
}

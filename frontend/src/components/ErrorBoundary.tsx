"use client";

/**
 * ErrorBoundary.tsx — traps React component crashes (Phase 9 / Prompt 166).
 *
 * On an error: the boundary records it, reports it through Sentry
 * (Sentry.captureException — a real event is created when a DSN is
 * configured; otherwise nothing is sent), and renders a recovery UI with:
 *   - a "Report Bug" action that opens Sentry's user-feedback dialog for the
 *     captured event (Sentry.showReportDialog) so the user can attach context;
 *   - a "Reload" action that resets the boundary and re-renders children.
 */
import { Component, type ErrorInfo, type ReactNode } from "react";
import * as Sentry from "@sentry/nextjs";
import { AlertTriangle, Bug, RotateCcw } from "lucide-react";
import { getSentryEnabled } from "@/lib/settings";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  eventId: string | undefined;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, eventId: undefined };

  static getDerivedStateFromError(): Partial<State> {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // The user-facing Settings page controls Sentry logging (real preference,
    // read live). When enabled, a real Sentry event is created (if a DSN is
    // configured); the eventId powers the Report Bug dialog below.
    const enabled = typeof window !== "undefined" && getSentryEnabled();
    if (!enabled) {
      this.setState({ eventId: undefined });
      return;
    }
    const eventId = Sentry.captureException(error, {
      extra: { componentStack: info.componentStack },
    });
    this.setState({ eventId });
  }

  private reportBug = () => {
    if (this.state.eventId) {
      Sentry.showReportDialog({ eventId: this.state.eventId });
    }
  };

  private reload = () => {
    this.setState({ hasError: false, eventId: undefined });
  };

  render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <div
        role="alert"
        style={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "linear-gradient(160deg, #0b0f1a 0%, #151a2e 100%)",
          color: "#e6e9f2",
          fontFamily: "system-ui, sans-serif",
          padding: "2rem",
        }}
      >
        <div style={{ maxWidth: 460, textAlign: "center" }}>
          <AlertTriangle size={44} style={{ color: "#ffb020", margin: "0 auto 1rem" }} />
          <h1 style={{ fontSize: "1.5rem", margin: "0 0 0.5rem" }}>Something went wrong</h1>
          <p style={{ color: "#9aa3bf", fontSize: "0.95rem", lineHeight: 1.6, margin: "0 0 1.5rem" }}>
            The interface hit an unexpected error. The details were captured for
            diagnostics — report it so we can fix it.
          </p>
          <div style={{ display: "flex", gap: "0.75rem", justifyContent: "center" }}>
            <button
              onClick={this.reportBug}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.5rem",
                padding: "0.7rem 1.1rem",
                borderRadius: 10,
                border: "none",
                background: "#4f6bff",
                color: "#fff",
                fontSize: "0.9rem",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              <Bug size={16} /> Report Bug
            </button>
            <button
              onClick={this.reload}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "0.5rem",
                padding: "0.7rem 1.1rem",
                borderRadius: 10,
                border: "1px solid #3a4157",
                background: "transparent",
                color: "#c9cfe4",
                fontSize: "0.9rem",
                cursor: "pointer",
              }}
            >
              <RotateCcw size={16} /> Reload
            </button>
          </div>
        </div>
      </div>
    );
  }
}

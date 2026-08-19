/**
 * sentry.client.config.ts — Sentry SRE for the browser bundle
 * (Phase 9 / Prompt 163).
 *
 * The DSN comes from NEXT_PUBLIC_SENTRY_DSN and is only set where crash
 * reporting is actually configured. When it is absent (local dev, CI,
 * fresh clone) Sentry is NOT initialized — the app runs with zero Sentry
 * network traffic and zero sent events. No fake DSN is ever used.
 */
import * as Sentry from "@sentry/nextjs";

const dsn = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (dsn) {
  Sentry.init({
    dsn,
    // 1.0 for a demo-scale client app; tighten for production traffic.
    tracesSampleRate: 1.0,
    debug: false,
  });
}

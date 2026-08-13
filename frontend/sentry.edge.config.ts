/**
 * sentry.edge.config.ts — Sentry SRE for the Next.js Edge Runtime
 * (middleware / edge API routes).
 *
 * Mirrors sentry.client.config.ts and sentry.server.config.ts: initialized
 * ONLY when a real DSN is configured (SENTRY_DSN). No DSN in the environment
 * -> no initialization, no fabricated reporting.
 */
import * as Sentry from "@sentry/nextjs";

const dsn = process.env.SENTRY_DSN;

if (dsn) {
  Sentry.init({
    dsn,
    tracesSampleRate: 1.0,
    debug: false,
  });
}

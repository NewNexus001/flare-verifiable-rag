/**
 * sentry.server.config.ts — Sentry SRE for the Next.js server runtime
 * (Phase 9 / Prompt 163).
 *
 * Same guard as the client config: initialized ONLY when a real DSN is
 * configured (SENTRY_DSN). No DSN in the environment -> no initialization,
 * no fabricated reporting.
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

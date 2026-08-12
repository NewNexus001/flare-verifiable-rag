/**
 * next.config.mjs — Next.js 14 build configuration (Phase 9 / Prompt 162).
 *
 * - `reactStrictMode: true` — the master-plan requirement (double-invokes
 *   effects in dev to surface bugs early).
 * - `withSentryConfig` — @sentry/nextjs 7.107.0 webpack integration for
 *   source maps + server instrumentation. The org/project/authToken come
 *   from the environment ONLY: when they are absent (CI / fresh clone) the
 *   plugin skips the upload step (silent) and the build still succeeds —
 *   no fake token is ever used (zero-mock policy).
 * - Security headers — a strict-but-safe baseline (no CSP yet: a mis-scoped
 *   CSP breaks the RainbowKit iframe on next dev; the rest costs nothing).
 */
import { withSentryConfig } from "@sentry/nextjs";

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

const sentryWebpackPluginOptions = {
  org: process.env.SENTRY_ORG,
  project: process.env.SENTRY_PROJECT,
  authToken: process.env.SENTRY_AUTH_TOKEN,
  // Secure default (v8 will default to true): source maps are NOT shipped to
  // the browser — original source stays out of devtools in production.
  hideSourceMaps: true,
  silent: true,
};

export default withSentryConfig(nextConfig, sentryWebpackPluginOptions);

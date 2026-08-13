/**
 * next.config.mjs — Next.js 14 build configuration.
 *
 * - `reactStrictMode: true` — double-invokes effects in dev to surface bugs
 *   early.
 * - `withSentryConfig` — @sentry/nextjs 7.107.0 webpack integration for
 *   source maps + server instrumentation. Applied ONLY when a real
 *   SENTRY_AUTH_TOKEN is present (CI with secrets / production): otherwise
 *   the plain config is exported, so a fresh clone or local build never
 *   hits the "No Sentry organization slug configured" failure mode. No
 *   placeholder credentials are ever used.
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

// Only engage the Sentry webpack plugin when real credentials exist; a bare
// build must succeed without any Sentry configuration.
export default process.env.SENTRY_AUTH_TOKEN
  ? withSentryConfig(nextConfig, sentryWebpackPluginOptions)
  : nextConfig;

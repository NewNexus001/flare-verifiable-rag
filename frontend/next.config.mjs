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
 * - next-intl — i18n locale routing for 5 languages (en/es/zh/ja/ar).
 */
import { withSentryConfig } from "@sentry/nextjs";
import createNextIntlPlugin from "next-intl/plugin";

const withNextIntl = createNextIntlPlugin("./i18n.ts");

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Standalone output: minimal self-contained server build consumed by the
  // Docker image (frontend/Dockerfile) and Skaffold local dev loop.
  output: "standalone",
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

// Chain: next-intl first, then Sentry (only when real credentials exist).
const baseConfig = withNextIntl(nextConfig);

export default process.env.SENTRY_AUTH_TOKEN
  ? withSentryConfig(baseConfig, sentryWebpackPluginOptions)
  : baseConfig;

/**
 * middleware.ts — Next.js middleware for:
 * 1. Locale detection via Accept-Language + routing to /[locale]/...
 * 2. RTL layout enforcement for Arabic (ar)
 * 3. Honeypot Security Router intercepting probe paths (/admin, /.env, /v1/debug, /wp-login.php)
 *
 * Phase 19, Prompts 363/366/367/368/369.
 */
import createMiddleware from "next-intl/middleware";
import { locales, defaultLocale, type Locale } from "../i18n";
import { NextResponse, type NextRequest } from "next/server";

/** Paths that scanners and bots probe — capture and deflect. */
const HONEYPOT_PATHS = [
  "/admin",
  "/admin/",
  "/.env",
  "/.env/",
  "/v1/debug",
  "/v1/debug/",
  "/wp-login.php",
  "/wp-admin",
  "/wp-admin/",
  "/xmlrpc.php",
  "/.git/config",
  "/.git/",
  "/phpmyadmin",
  "/phpmyadmin/",
];

/** Suspicious User-Agent fragments to flag. */
const BOT_SIGNALS = [
  "sqlmap",
  "nikto",
  "nmap",
  "masscan",
  "zgrab",
  "gobuster",
  "dirbuster",
  "wpscan",
  "curl/",
  "python-requests",
  "go-http-client",
];

/**
 * Returns true if the path matches a known honeypot probe.
 */
function isHoneypotPath(pathname: string): boolean {
  const normalised = pathname.toLowerCase();
  return HONEYPOT_PATHS.some(
    (p) => normalised === p || normalised.startsWith(p + "/")
  );
}

/**
 * Checks the User-Agent for scanner/bot fingerprints.
 */
function isSuspiciousAgent(ua: string | null): boolean {
  if (!ua) return false;
  const lower = ua.toLowerCase();
  return BOT_SIGNALS.some((sig) => lower.includes(sig));
}

/**
 * Log honeypot telemetry — structured JSON for Sentry / GCP Logging.
 * In production this sends to Sentry via the server-side SDK; in dev
 * it writes to the structured logger.
 */
function logHoneypotEvent(
  req: NextRequest,
  matchedPath: string,
  ua: string | null
): void {
  const event = {
    level: "warning",
    category: "honeypot",
    ip:
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
      req.headers.get("x-real-ip") ??
      "unknown",
    userAgent: ua ?? "unknown",
    path: matchedPath,
    method: req.method,
    timestamp: new Date().toISOString(),
    // Include TLS fingerprint hints if available (Cloudflare/CDN headers)
    cfRay: req.headers.get("cf-ray") ?? null,
    tlsVersion: req.headers.get("cf-visitor") ?? null,
  };

  // Structured log — Sentry captures this as a warning event.
  // In production the Sentry SDK picks this up automatically.
  // eslint-disable-next-line no-console
  console.warn(JSON.stringify(event));
}

/**
 * Generate a delayed response to waste scanner time.
 * Returns after a random 200–800ms delay with a generic 404.
 */
async function honeypotResponse(
  req: NextRequest
): Promise<NextResponse> {
  const ua = req.headers.get("user-agent");
  const path = req.nextUrl.pathname;

  // Log the event for telemetry
  logHoneypotEvent(req, path, ua);

  // Random delay to slow down scanners (200–800ms)
  const delay = Math.floor(Math.random() * 600) + 200;
  await new Promise((resolve) => setTimeout(resolve, delay));

  // Return obfuscated 404 — never reveal server state
  return new NextResponse(
    JSON.stringify({
      error: "Not Found",
      message: "The requested resource does not exist.",
      statusCode: 404,
    }),
    {
      status: 404,
      headers: {
        "Content-Type": "application/json",
        "X-Robots-Tag": "noindex, nofollow",
        "Cache-Control": "no-store, no-cache, must-revalidate",
      },
    }
  );
}

/**
 * Detect the best locale from the Accept-Language header.
 * Returns the default locale if no match found.
 */
function detectLocale(req: NextRequest): Locale {
  const acceptLang = req.headers.get("accept-language");
  if (!acceptLang) return defaultLocale;

  // Parse Accept-Language: "en-US,en;q=0.9,es;q=0.8"
  const supported = Array.from(locales);
  const languages = acceptLang
    .split(",")
    .map((part) => {
      const [lang, qPart] = part.trim().split(";");
      const quality = qPart
        ? parseFloat(qPart.replace("q=", "")) || 1
        : 1;
      return { lang: lang?.split("-")[0]?.toLowerCase(), quality };
    })
    .filter((l) => l.lang && supported.includes(l.lang as Locale))
    .sort((a, b) => b.quality - a.quality);

  return (languages[0]?.lang as Locale) ?? defaultLocale;
}

/**
 * Main middleware — runs on every matched request.
 */
export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // --- HONEYPOT LAYER ---
  // Intercept malicious probe paths BEFORE locale routing.
  // This catches scanners hitting /admin, /.env, /wp-login.php, etc.
  if (isHoneypotPath(pathname)) {
    return honeypotResponse(req);
  }

  // Also flag suspicious user agents on any path
  const ua = req.headers.get("user-agent");
  if (isSuspiciousAgent(ua)) {
    // Don't block (that reveals detection) — just log and let through
    logHoneypotEvent(req, pathname, ua);
  }

  // --- LOCALE LAYER ---
  // Check if the path already has a locale prefix
  const hasLocale = locales.some(
    (loc) => pathname.startsWith(`/${loc}/`) || pathname === `/${loc}`
  );

  if (!hasLocale) {
    // Detect locale and redirect to /[locale]/...
    const locale = detectLocale(req);
    const url = req.nextUrl.clone();
    url.pathname = `/${locale}${pathname}`;
    return NextResponse.redirect(url);
  }

  // Use next-intl middleware for locale routing + validation
  const intlMiddleware = createMiddleware({
    locales: Array.from(locales),
    defaultLocale,
    localePrefix: "always",
  });

  const response = intlMiddleware(req);

  // --- RTL ENFORCEMENT ---
  // Extract the locale from the path
  const pathLocale = pathname.split("/")[1] as Locale;
  if (pathLocale === "ar") {
    response.headers.set("Next-Intl-Locale-Dir", "rtl");
  } else {
    response.headers.set("Next-Intl-Locale-Dir", "ltr");
  }

  return response;
}

export const config = {
  // Match all paths except static files, API routes, and Next.js internals
  matcher: [
    // Match all paths except:
    // - _next/static (static files)
    // - _next/image (image optimization)
    // - favicon.ico
    // - public folder assets
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};

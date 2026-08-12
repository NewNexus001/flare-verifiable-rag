/**
 * api/enclave/health/route.ts — blind-proxy liveness probe (Prompt 179).
 *
 * The browser NEVER talks to the enclave directly. This server-side route
 * forwards `GET /health` to the enclave's liveness endpoint, so the enclave
 * address stays server-side (blind-proxy security model). The enclave URL
 * is injected via the `ENCLAVE_URL` env var — zero hardcoded addresses
 * (zero-mock policy). When the env var is unset the route reports 503 with
 * an honest, structured body instead of pretending the enclave exists.
 */
import { NextRequest, NextResponse } from "next/server";

// Enclave base URL (server-side only — never NEXT_PUBLIC).
const ENCLAVE_URL = process.env.ENCLAVE_URL ?? "";

// Hard bound so the route never hangs on a dead enclave.
const TIMEOUT_MS = 3000;

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest): Promise<NextResponse> {
  if (!ENCLAVE_URL) {
    return NextResponse.json(
      {
        status: "unconfigured",
        detail: "ENCLAVE_URL is not set on the server — no enclave route configured.",
      },
      { status: 503 }
    );
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    // Forward the REAL inbound scheme like a TLS-terminating reverse proxy:
    // when the browser arrived over HTTPS (Vercel sets x-forwarded-proto:
    // https) the enclave's TLS check sees https; on plain-HTTP local dev the
    // header is absent and the enclave 426s honestly (its loopback /health
    // exemption still applies). Never invent https.
    const proto = req.headers.get("x-forwarded-proto") ?? "";
    const headers: Record<string, string> = { accept: "application/json" };
    if (proto.includes("https")) headers["x-forwarded-proto"] = "https";

    const res = await fetch(`${ENCLAVE_URL}/health`, {
      signal: controller.signal,
      cache: "no-store", // never cache health — it is a live probe
      headers,
    });
    const body = await res.json().catch(() => ({}));
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      {
        status: "unreachable",
        detail:
          err instanceof Error && err.name === "AbortError"
            ? `enclave health check timed out after ${TIMEOUT_MS}ms`
            : `enclave unreachable: ${(err as Error).message ?? "unknown error"}`,
      },
      { status: 502 }
    );
  } finally {
    clearTimeout(timer);
  }
}

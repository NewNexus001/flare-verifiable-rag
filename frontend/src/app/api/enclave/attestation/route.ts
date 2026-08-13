/**
 * api/enclave/attestation/route.ts — blind-proxy to the enclave's
 * /v1/attestation state endpoint (Prompt 170 backend).
 *
 * The enclave's AttestationStateResponse (real vTPM OIDC claims: swname,
 * image_digest, instance_id, hardware, token validity) is fetched
 * server-side and relayed. Fail-closed: a 503 from the enclave (unproven
 * attestation) is relayed as-is so the badge can render the honest state.
 */
import { NextRequest, NextResponse } from "next/server";

const ENCLAVE_URL = process.env.ENCLAVE_URL ?? "";
const TIMEOUT_MS = 3000;

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest): Promise<NextResponse> {
  if (!ENCLAVE_URL) {
    return NextResponse.json(
      {
        status: "unconfigured",
        detail: "The attestation service is not deployed. Configure ENCLAVE_URL to enable live hardware attestation.",
      },
      { status: 503 }
    );
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    // Same TLS-terminating-proxy protocol forwarding as the /health route:
    // pass the REAL inbound scheme through; never invent https.
    const proto = req.headers.get("x-forwarded-proto") ?? "";
    const headers: Record<string, string> = { accept: "application/json" };
    if (proto.includes("https")) headers["x-forwarded-proto"] = "https";

    const res = await fetch(`${ENCLAVE_URL}/v1/attestation`, {
      signal: controller.signal,
      cache: "no-store",
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
            ? `enclave attestation check timed out after ${TIMEOUT_MS}ms`
            : `enclave unreachable: ${(err as Error).message ?? "unknown error"}`,
      },
      { status: 502 }
    );
  } finally {
    clearTimeout(timer);
  }
}

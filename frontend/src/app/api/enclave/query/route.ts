/**
 * api/enclave/query/route.ts — blind-proxy POST /v1/query (Prompt 174).
 *
 * The browser posts ONLY the AES-GCM-256 ciphertext envelope to this
 * same-origin route; the server relays it to the enclave's /v1/query and
 * returns the enclave's encrypted response envelope. Nothing is cached
 * locally (cache: "no-store", no persistent storage, no disk writes) —
 * the plaintext never exists outside the browser and the TEE. The enclave
 * address is server-side only.
 *
 * Security: the request body is validated to be a small JSON envelope
 * ({ payload: string }), size-capped server-side, and forwarded verbatim.
 */
import { NextRequest, NextResponse } from "next/server";

const ENCLAVE_URL = process.env.ENCLAVE_URL ?? "";
const TIMEOUT_MS = 70000; // matches the enclave QUERY_TIMEOUT_S=60 + margin
const MAX_BODY_BYTES = 1024 * 1024; // enclave middleware cap (1 MiB)

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!ENCLAVE_URL) {
    return NextResponse.json(
      { status: "unconfigured", detail: "ENCLAVE_URL is not set on the server." },
      { status: 503 }
    );
  }

  let payload: unknown;
  try {
    payload = await req.json();
  } catch {
    return NextResponse.json(
      { detail: "invalid_request", title: "request body is not valid JSON" },
      { status: 400 }
    );
  }

  // Strict wire contract (matches the enclave EncryptedQueryRequest model,
  // extra="forbid"): exactly { payload: string }.
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("payload" in payload) ||
    typeof (payload as Record<string, unknown>).payload !== "string"
  ) {
    return NextResponse.json(
      { detail: "invalid_request", title: "expected { payload: string }" },
      { status: 400 }
    );
  }
  const envelope = (payload as { payload: string }).payload;
  if (Buffer.byteLength(envelope, "utf8") > MAX_BODY_BYTES) {
    return NextResponse.json(
      {
        detail: "payload_too_large",
        title: `envelope exceeds ${MAX_BODY_BYTES} bytes`,
      },
      { status: 413 }
    );
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`${ENCLAVE_URL}/v1/query`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ payload: envelope }),
      signal: controller.signal,
      cache: "no-store", // blind proxy: never cache ciphertext responses
    });
    const body = await res.json().catch(() => ({}));
    // Relay the enclave's status verbatim (200 envelope | 4xx/5xx problem).
    return NextResponse.json(body, { status: res.status });
  } catch (err) {
    return NextResponse.json(
      {
        detail:
          err instanceof Error && err.name === "AbortError"
            ? "enclave query timed out"
            : `enclave unreachable: ${(err as Error).message ?? "unknown error"}`,
        title: "enclave_query_failed",
      },
      { status: 502 }
    );
  } finally {
    clearTimeout(timer);
  }
}

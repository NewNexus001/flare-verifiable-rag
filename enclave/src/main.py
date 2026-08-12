"""Secure Enclave FastAPI gateway — Phase 4 / Prompt 063.

Initializes the enclave's HTTP surface with two security controls, both
research-backed (user-provided research + Starlette/FastAPI docs, 2026-08-06):

1. **Restricted CORS** — an explicit, env-configured origin allowlist
   (`ENCLAVE_CORS_ORIGINS`). No wildcard. This is the gold-standard pattern:
   strict string-equality matching, and `allow_credentials=True` is legal
   only because we never emit `Access-Control-Allow-Origin: *` (the Fetch
   spec rejects wildcards with credentials).

2. **Strict TLS payload validation** — an ASGI middleware that:
   a. Rejects any request that did not arrive over TLS. Two deployment
      shapes are supported, because the enclave can be reached either
      directly (uvicorn terminates TLS: `scope["scheme"] == "https"`) or
      behind the Confidential Space / reverse-proxy hop that terminates TLS
      and forwards plain HTTP with `X-Forwarded-Proto: https` (or the
      standard `Forwarded: proto=https`). In the proxy case the app-internal
      scheme is `http`, so we MUST inspect the proxy headers — checking
      `request.url.scheme` alone would reject every legitimate request.
   b. Enforces payload framing: body-bearing methods must declare an
      allowed Content-Type, and payload size is capped (413 on exceed).
      A strict, non-wildcard Content-Type allowlist is the OWASP-recommended
      pattern for API ingress (no `*/*`, no `text/html`, no forms).

   The single loopback exception: `GET /health` from a loopback client
   (`127.0.0.1` / `::1`) is always allowed even over plain HTTP, because the
   container HEALTHCHECK (enclave/Dockerfile) probes it with plain HTTP and
   TLS cannot be terminated by the healthcheck client. This is a documented,
   deliberately narrow exception.

Environment configuration (zero hardcoded values — zero-mock policy):
  ENCLAVE_CORS_ORIGINS          comma-separated allowlist; default "" (deny all)
  ENCLAVE_MAX_PAYLOAD_BYTES     payload cap; default 1 MiB
  ENCLAVE_ALLOWED_CONTENT_TYPES comma-separated; default application/json

The gateway surface (Phase 4, Prompt 077): `/health` (liveness probe with
bounded REAL Coston2 RPC + vTPM attestation dependency checks and a
secret-free config snapshot) and `/v1/query` (POST a base64 AES-GCM-256
envelope; the enclave decrypts in RAM, runs the REAL Rust symbolic engine
via PyO3, and returns the execution record encrypted for the blind proxy).
Phase 5 (Prompt 081/082) adds `/attestation` — the fail-closed authority
that fetches REAL hardware measurements from the local vTPM tee server and
503s when attestation cannot be proven. Prompt 096 adds the
``AttestationGateMiddleware``: when ``ENCLAVE_REQUIRE_ATTESTATION=1`` it
blocks ``POST /v1/query`` with RFC 7807 503 ``attestation_required`` unless
the background-refreshed attestation cache holds a valid, unexpired token
(production cache-only pattern — no per-request vTPM quote; ``/health`` and
``/v1/attestation`` stay exempt so orchestrators can diagnose an unproven
node).

No host-header middleware (TrustedHostMiddleware) is added ON PURPOSE: the
enclave is only reachable through the trusted reverse proxy / Confidential
Space launcher, which terminates TLS and routes on the Host header itself.
Enforcing our own Host allowlist here would risk rejecting the proxy's
legitimate Host and adds no security boundary that the TLS + proxy checks do
not already provide.

SECURITY ASSUMPTION (deployment contract): the TLS-terminating reverse proxy
in front of the enclave MUST (a) overwrite inbound `X-Forwarded-Proto` /
`Forwarded` headers (never pass client-supplied values through) and (b) enforce
its own request-body size limits. This module's TLS detection trusts those
proxy headers by design; if the enclave is ever exposed without such a proxy,
the 426 enforcement can be bypassed by a forged `X-Forwarded-Proto: https`.
"""

import asyncio
import base64
import binascii
import dataclasses
import datetime
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import timezone
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.base import BaseHTTPMiddleware

from src.config import get_settings
from src.crypto.attestation import (
    ATTESTATION_ENDPOINT,
    INTEL_TOKEN_ENDPOINT,
    TEESERVER_SOCKET,
    AttestationEngine,
    AttestationError,
    AttestationServiceUnavailableError,
    AttestationStateCache,
    IntelAttestationToken,
)
from src.crypto.encryption import (
    ClientPayloadCipher,
    DecryptionError,
    MAX_ENCRYPTED_PAYLOAD_BYTES,
    PayloadFormatError,
    PayloadKeyError,
)
from src.crypto.jwt_parser import verify_confidential_space_claims
from src.rag_engine.processor import EphemeralProcessor, get_ephemeral_processor

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment configuration (parsed once at import; no hardcoded secrets/URLs)
# ---------------------------------------------------------------------------

APP_NAME = os.environ.get("ENCLAVE_APP_NAME", "flare-verifiable-rag-enclave")

# Comma-separated origin allowlist. Default: empty → cross-origin requests are
# denied entirely (no Access-Control-Allow-Origin is emitted for any Origin).
_CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("ENCLAVE_CORS_ORIGINS", "").split(",")
    if o.strip()
]

# Payload size cap (bytes). Default 1 MiB — generous for JSON-RPC payloads,
# tight enough to bound the in-memory attack surface of the enclave. A
# non-numeric value falls back to the documented default instead of crashing
# the process at import (config robustness).
try:
    MAX_PAYLOAD_BYTES = int(os.environ.get("ENCLAVE_MAX_PAYLOAD_BYTES", "1048576"))
except ValueError:
    MAX_PAYLOAD_BYTES = 1024 * 1024

# Strict Content-Type allowlist for body-bearing methods. The blueprint's
# client ships AES-GCM-256 ciphertext; later prompts may add
# `application/octet-stream` here explicitly when the binary payload schema
# is defined. JSON is the only accepted type today.
_ALLOWED_CONTENT_TYPES = {
    t.strip().lower()
    for t in os.environ.get("ENCLAVE_ALLOWED_CONTENT_TYPES", "application/json").split(",")
    if t.strip()
}

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# ---------------------------------------------------------------------------
# Endpoint constants (Phase 4 / Prompt 077)
# ---------------------------------------------------------------------------

# Process start time — baseline for /health uptime.
_BOOT_TIME = time.monotonic()
# Hard deadline for ONE query (decrypt + symbolic prove). The Rust FFI
# releases the GIL, so the event loop stays responsive; this deadline
# bounds the worst-case response time. NOTE: asyncio.wait_for cancels the
# awaiting task — the CPU-bound worker thread runs to completion in the
# background (documented threadpool semantics).
QUERY_TIMEOUT_S = 60.0
# Bounded budget for the /health live RPC dependency check (never hangs).
RPC_HEALTH_TIMEOUT_S = 2.0
# Bounded budget for the /health vTPM attestation status check (never
# hangs; connection-refused on a dev box resolves in milliseconds anyway).
ATTESTATION_HEALTH_TIMEOUT_S = 1.0
# Hard deadline for the /attestation endpoint fetch. The fallback flow
# (Prompt 083) runs up to TWO bounded fetches (primary + Intel TDX), each
# self-bound at (DEFAULT_TIMEOUT_S + 1.0) = 6.0s with the 5.0 default, so
# the worst case is ~12s; this outer bound (strictly larger, defense-in-
# depth) only fires if the engine's internal bounds were misconfigured.
ATTESTATION_FETCH_TIMEOUT_S = 15.0
# Context binding for the outbound response envelope (composed AAD).
QUERY_CONTEXT_AAD = "/v1/query"

# Local GCP TEE server (Confidential Space vTPM agent) contact points — the
# canonical launcher values from the research. Env-overridable so local
# verification can point a REAL tee server at a test port; defaults are
# exactly the documented launcher contract.
_ATTESTATION_ENDPOINT = os.environ.get(
    "ENCLAVE_ATTESTATION_ENDPOINT", ATTESTATION_ENDPOINT
)
_INTEL_ATTESTATION_ENDPOINT = os.environ.get(
    "ENCLAVE_INTEL_ATTESTATION_ENDPOINT", INTEL_TOKEN_ENDPOINT
)
_TEESERVER_SOCKET = os.environ.get(
    "ENCLAVE_TEESERVER_SOCKET", TEESERVER_SOCKET
)

# ---------------------------------------------------------------------------
# Middleware: strict TLS + payload validation
# ---------------------------------------------------------------------------


class TlsAndPayloadValidationMiddleware(BaseHTTPMiddleware):
    """Enforces (a) TLS-only ingress and (b) strict payload framing.

    Runs outermost so that a non-TLS request is rejected before any CORS or
    route logic executes.
    """

    def __init__(self, app):
        super().__init__(app)
        self.max_payload_bytes = MAX_PAYLOAD_BYTES
        self.allowed_content_types = _ALLOWED_CONTENT_TYPES

    @staticmethod
    def _is_loopback(request: Request) -> bool:
        host = request.client.host if request.client else ""
        return host in ("127.0.0.1", "::1", "localhost")

    @staticmethod
    def _arrived_over_tls(request: Request) -> bool:
        # Direct TLS termination by uvicorn.
        if request.scope.get("scheme") == "https":
            return True
        # Behind a TLS-terminating reverse proxy (X-Forwarded-Proto).
        xfp = request.headers.get("x-forwarded-proto", "")
        if "https" in [p.strip().lower() for p in xfp.split(",")]:
            return True
        # RFC 7239 Forwarded header form: Forwarded: proto=https.
        # Exact token match (no prefix matching) — stricter and rejects
        # malformed values like `proto=httpsfoo`.
        fwd = request.headers.get("forwarded", "").lower()
        return any(
            part.strip() == "proto=https"
            for part in fwd.split(";")
            if part.strip()
        )

    async def dispatch(self, request: Request, call_next):
        # The one documented loopback exception: the container HEALTHCHECK
        # (plain HTTP, GET /health from 127.0.0.1) must always pass.
        if (
            request.method == "GET"
            and request.url.path == "/health"
            and self._is_loopback(request)
        ):
            return await call_next(request)

        # (a) TLS enforcement — 426 Upgrade Required is the correct semantic
        #     for an API that must REJECT (not redirect) plain HTTP.
        if not self._arrived_over_tls(request):
            return JSONResponse(
                status_code=426,
                content={
                    "detail": "TLS required",
                    "reason": "this endpoint only accepts HTTPS requests",
                },
                headers={"Connection": "close"},
            )

        # (b) Payload framing for body-bearing methods.
        if request.method in _BODY_METHODS:
            content_type = request.headers.get("content-type", "")
            base_type = content_type.split(";")[0].strip().lower()
            if base_type not in self.allowed_content_types:
                return JSONResponse(
                    status_code=415,
                    content={
                        "detail": "unsupported media type",
                        "allowed": sorted(self.allowed_content_types),
                        "received": base_type or "(none)",
                    },
                )

            content_length = request.headers.get("content-length")
            if content_length is not None and content_length.isdigit():
                # Fast path: declared size over the cap is rejected WITHOUT
                # buffering the body (no memory cost for oversized uploads).
                declared = int(content_length)
                if declared > self.max_payload_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": "payload too large",
                            "max_bytes": self.max_payload_bytes,
                            "received_bytes": declared,
                        },
                    )
            else:
                # Chunked / missing / malformed Content-Length: read and cap.
                # NOTE: Starlette caches the body, so downstream handlers can
                # still read it after this check — but an unbounded chunked
                # stream is buffered up to EOF before rejection. This is the
                # pragmatic ASGI pattern (consuming request.stream() would
                # break downstream reads) and is acceptable ONLY because the
                # TLS-terminating proxy in front of the enclave enforces its
                # own request-body limits; see the module docstring.
                body = await request.body()
                if len(body) > self.max_payload_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": "payload too large",
                            "max_bytes": self.max_payload_bytes,
                        },
                    )

        return await call_next(request)


class AttestationGateMiddleware(BaseHTTPMiddleware):
    """Prompt 096 — fail-closed gate blocking /v1/query on invalid attestation.

    The production state-snapshot pattern (Prompt 088 research + user
    cross-checked design, 2026-08-09): the gate reads the
    BACKGROUND-REFRESHED attestation cache (``app.state.attestation_cache``)
    — a zero-latency in-memory check. There is NO per-request vTPM quote
    (hardware token generation costs 100ms-2s and is rate-limited; the
    cache loop maintains the current state and renews before expiry).

    Semantics (cache-only, user-approved):

    * ``ENCLAVE_REQUIRE_ATTESTATION`` OFF (default) → pass-through (local
      dev + Docker smoke run without a tee server).
    * Flag ON + cache established + token unexpired → pass.
    * Flag ON + cache NEVER established OR held token EXPIRED → RFC 7807
      503 ``attestation_required`` — never 200 with a degraded state.
    * Flag ON + no cache on ``app.state`` (lifespan not run) → fail closed
      503 (defensive; the cache is always installed by lifespan).
    * A still-valid cached token survives a transient tee-server outage —
      the held token only expires via its own ``exp`` claim, so queries
      keep flowing until it genuinely expires (immediate revocation would
      require a per-request fetch — the anti-pattern this design replaces).

    Gated path: exactly ``POST /v1/query`` (the sensitive processing
    endpoint). ``/health``, ``/attestation`` and ``/v1/attestation`` are
    deliberately EXEMPT — orchestrators must be able to probe and diagnose
    an unproven node (research: never trap the health probe in the gate).
    ``POST /v1/attestation-proof`` is ALSO not gated here — it
    self-protects via its own fresh vTPM fetch + fail-closed 503
    (``attestation_unavailable``), so gating it on the cache too would be
    redundant.

    NOTE (middleware ordering): CORS is registered INNER to this gate
    (order: TLS → gate → CORS → routes), so a gated 503 does not pass back
    through CORS and carries no CORS headers. That is intentional — the
    enclave's client is the server-to-server blind proxy, not a browser;
    only direct browser clients would observe the missing headers.
    """

    GATED_PATH = "/v1/query"
    GATED_METHODS = frozenset({"POST"})

    async def dispatch(self, request: Request, call_next):
        if not _attestation_required():
            return await call_next(request)
        if (
            request.method in self.GATED_METHODS
            and request.url.path == self.GATED_PATH
        ):
            cache: AttestationStateCache | None = getattr(
                request.app.state, "attestation_cache", None
            )
            try:
                if cache is None:
                    raise AttestationServiceUnavailableError(
                        "attestation cache not initialized (lifespan did not run)"
                    )
                cache.snapshot()  # raises on never-established OR expired
            except AttestationError as exc:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "type": "about:blank",
                        "title": "attestation_required",
                        "status": status.HTTP_503_SERVICE_UNAVAILABLE,
                        "detail": str(exc),
                    },
                    headers={"Retry-After": "10"},
                )
        return await call_next(request)


# ---------------------------------------------------------------------------
# API request/response models (Pydantic v2) — Phase 4 / Prompt 064
# ---------------------------------------------------------------------------
#
# These schemas are the enclave's public API contract, aligned with the
# blueprint's data flows: the deterministic symbolic engine digests documents
# and prompts (H_doc / H_prompt), returns an exact evidence subgraph (Path),
# and generates a halo2 ZK proof bound to the three hashes; the vTPM/OIDC
# attestation claims carry swname + image digest. Models are strict
# (extra="forbid") so unknown payload fields are rejected — the
# research-backed production pattern (Pydantic v2 ConfigDict).

# A SHA-256 digest as 64 lowercase hex chars — the canonical form of H_doc,
# H_prompt, and H_out produced by the Rust engine's digest_to_field pipeline.
Sha256Hex = Annotated[
    str,
    Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 digest, lowercase hex"),
]

# The serialized symbolic-graph evidence subgraph returned by the Rust
# engine's `KnowledgeGraph::find_path` (serde JSON). Typed as an opaque
# JSON object here; the exact Path schema is validated by the engine's own
# serializer before it crosses the FFI boundary.
EvidenceSubgraph = dict[str, Any]


class QueryRequest(BaseModel):
    """A verifiable-RAG query against the enclave's knowledge corpus.

    NOTE: this model describes the **decrypted** contract. The client (Next.js
    blind proxy) encrypts the payload with AES-GCM-256 before transport; the
    enclave decrypts it inside the TEE, and only then is the plaintext parsed
    into this model. The query text becomes the formal logical predicate; the
    optional document_hashes scope the search to exact documents.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    query: Annotated[
        str,
        Field(
            min_length=1,
            max_length=4096,
            description="The natural-language prompt to resolve symbolically",
        ),
    ]

    document_hashes: Annotated[
        list[Sha256Hex],
        Field(
            default_factory=list,
            max_length=64,
            description=(
                "Optional SHA-256 digests of documents to scope the query to; "
                "empty = search the whole corpus"
            ),
        ),
    ]


class QueryResponse(BaseModel):
    """The verifiable answer: output, exact evidence subgraph, and the
    halo2 proof binding H_doc / H_prompt / H_out to that output.

    The on-chain verifier (VerifiableRAG.sol, later phases) re-derives the
    public inputs from the returned hashes and checks the proof against the
    enclave's registered verifying key.
    """

    model_config = ConfigDict(extra="forbid")

    query_hash: Sha256Hex = Field(description="H_prompt — SHA-256 of the query")

    answer: Annotated[
        str,
        Field(min_length=1, max_length=65536, description="The resolved answer text"),
    ]

    evidence: EvidenceSubgraph = Field(
        description="Exact symbolic-graph evidence subgraph (Path JSON)"
    )

    proof: Annotated[
        str,
        Field(
            description=(
                "halo2 ZK proof bytes, base64-encoded (Blake2b transcript)"
            )
        ),
    ]

    public_inputs: Annotated[
        list[Sha256Hex],
        Field(min_length=3, max_length=3, description="[H_doc, H_prompt, H_out]"),
    ]

    latency_ms: Annotated[
        int | None,
        Field(ge=0, description="Enclave processing time, milliseconds"),
    ] = None


class AttestationStatusResponse(BaseModel):
    """Hardware-attestation status, derived from the vTPM OIDC token claims
    (Confidential Space: http://localhost/v1/token).

    Mirrors the blueprint's access rule: access is granted iff
    swname == "CONFIDENTIAL_SPACE" AND image_digest matches the digest
    registered in the Workload Identity Pool attribute condition.
    """

    model_config = ConfigDict(extra="forbid")

    attested: bool = Field(description="Whether a valid vTPM OIDC token was obtained")

    swname: Annotated[
        str,
        Field(description="Software name claim, e.g. CONFIDENTIAL_SPACE"),
    ]

    image_digest: Annotated[
        str,
        Field(
            pattern=r"^sha256:[0-9a-f]{64}$",
            description="SHA-256 digest of the running container image "
            "(submods.container.image_digest claim, Prompt 085)",
        ),
    ]

    instance_id: Annotated[
        str | None,
        Field(
            default=None,
            description="GCE instance id (submods.gce.instance_id claim, "
            "Prompt 085); None when the token omits the gce submodule",
        ),
    ]

    hardware: Literal["AMD SEV-SNP", "Intel TDX", "unknown"] = Field(
        description="Attesting TEE hardware family"
    )

    token_issued_at: datetime.datetime | None = Field(
        default=None,
        description="OIDC token iat claim (None if not attested)",
    )

    intel: "IntelAttestationStatus | None" = Field(
        default=None,
        description=(
            "Validated Intel Trust Authority measurements when the enclave "
            "is attested on Intel TDX (Prompt 083 followup); None otherwise"
        ),
    )


class AttestationStateResponse(BaseModel):
    """Current enclave hardware-attestation STATE snapshot (Prompt 088).

    Derived metadata ONLY — never the raw vTPM JWT (blind-proxy best
    practice, user-pro-verified research: raw bearer tokens on status
    endpoints leak into proxy logs and enable replay; the token is
    isolated to ``POST /v1/attestation-proof`` for the on-chain relying
    party). Read from the background-refreshed attestation cache — no
    blocking hardware quote per call (vTPM quote generation is expensive
    and rate-limited). Fail-closed: this model is only ever returned with
    HTTP 200 when attestation is PROVEN; unproven/expired state is HTTP
    503 — never 200 with ``attested=false``, so load balancers and blind
    proxies evict the node.
    """

    model_config = ConfigDict(extra="forbid")

    attested: bool = Field(
        description="True by construction on 200 — attestation was proven "
        "(never returned with False; unproven state is HTTP 503)",
    )

    swname: str = Field(description="Software name claim (CONFIDENTIAL_SPACE)")

    image_digest: Annotated[
        str,
        Field(
            pattern=r"^sha256:[0-9a-f]{64}$",
            description="Attested container image digest "
            "(submods.container.image_digest claim)",
        ),
    ]

    instance_id: Annotated[
        str | None,
        Field(
            default=None,
            description="GCE instance id (submods.gce.instance_id claim); "
            "None when the token omits the gce submodule",
        ),
    ]

    hardware: Literal["AMD SEV-SNP", "Intel TDX", "unknown"] = Field(
        description="Attesting TEE hardware family"
    )

    token_issued_at: datetime.datetime | None = Field(
        default=None, description="vTPM token iat claim"
    )

    token_expires_at: datetime.datetime | None = Field(
        default=None, description="vTPM token exp claim (when the attestation expires)"
    )

    validity_seconds_remaining: Annotated[
        int | None,
        Field(
            ge=0,
            description="Seconds until the attestation expires (None when the "
            "token omits exp) — orchestrators see when renewal is expected",
        ),
    ] = None

    confidential_space: bool = Field(
        description="CEL identity gate result: swname == 'CONFIDENTIAL_SPACE' "
        "(Prompt 086)"
    )

    intel: "IntelAttestationStatus | None" = Field(
        default=None,
        description=(
            "Validated Intel Trust Authority measurements when the enclave "
            "is attested on Intel TDX; None otherwise"
        ),
    )


class AttestationProofResponse(BaseModel):
    """The combined hardware + execution attestation proof (Prompt 087).

    Binds the vTPM attestation token (raw JWT for the relying party), the
    attested container image digest, and the Rust halo2 ZKP proof with its
    three public inputs — plus the recomputable binding hash so an on-chain
    verifier can reject a swapped digest/proof pair. Strict
    (``extra="forbid"``); the raw JWT is retained for the later on-chain
    verification phase (VerifiableRAG.sol).
    """

    model_config = ConfigDict(extra="forbid")

    attested: bool = Field(default=True, description="Token + proof both validated")

    swname: str = Field(description="Software name claim (CONFIDENTIAL_SPACE)")

    image_digest: Annotated[
        str,
        Field(
            pattern=r"^sha256:[0-9a-f]{64}$",
            description="Attested container image digest (submods.container.image_digest)",
        ),
    ]

    hardware: Literal["AMD SEV-SNP", "Intel TDX", "unknown"] = Field(
        description="Attesting TEE hardware family"
    )

    zk_proof: Annotated[
        str,
        Field(description="halo2 ZK proof bytes, base64-encoded"),
    ]

    public_inputs: Annotated[
        list[Sha256Hex],
        Field(min_length=3, max_length=3, description="[H_doc, H_prompt, H_out]"),
    ]

    binding_hash: Sha256Hex = Field(
        description="SHA-256(image_digest || zk_proof || public_inputs) "
        "binding the attested image to the exact proof"
    )

    token: Annotated[
        str,
        Field(description="Raw vTPM OIDC attestation JWT (relying-party signature check)"),
    ]


class IntelAttestationStatus(BaseModel):
    """Validated Intel Trust Authority (ITA) measurements, surfaced when the
    /attestation endpoint detects Intel TDX (Prompt 083 followup).

    Mirrors ``IntelAttestationToken.get_measurements()``: the independent
    third-party hardware attestation (TDX quote, Intel appraisal policy
    results) alongside the primary Google attestation status.
    """

    model_config = ConfigDict(extra="forbid")

    attested: bool = Field(default=True, description="ITA token validated")

    issuer: Annotated[
        str,
        Field(description="Intel Trust Authority issuer"),
    ]

    hwmodel: Annotated[
        str,
        Field(description="Hardware model claim (GCP_INTEL_TDX on TDX)"),
    ]

    attester_tcb: Annotated[
        list[str],
        Field(description="Hardware root-of-trust list (e.g. [INTEL])"),
    ]

    tdx_quote: dict[str, Any] | None = Field(
        default=None, description="Raw Intel TDX quote measurements"
    )

    policy_ids_matched: Annotated[
        list[str],
        Field(description="Intel appraisal policy UUIDs that passed"),
    ] = Field(default_factory=list)

    policy_ids_unmatched: Annotated[
        list[str],
        Field(description="Intel appraisal policy UUIDs that failed"),
    ] = Field(default_factory=list)

    token_issued_at: datetime.datetime | None = Field(
        default=None, description="ITA token iat claim"
    )


class EncryptedQueryRequest(BaseModel):
    """The client's POST body for `/v1/query`: the AES-GCM-256 envelope,
    base64-encoded (standard or URL-safe alphabet, padding optional).

    Wire contract (matches processor.py / crypto.encryption, Prompt
    066/071-verified): the client encrypts `{"document": str, "prompt": str}`
    under `ENCLAVE_PAYLOAD_KEY` with AES-GCM-256 and the protocol AAD,
    producing `nonce(12) || ciphertext || tag(16)`. The envelope is decoded
    and decrypted ONLY inside the TEE. Strict (`extra="forbid"`): unknown
    fields are rejected with 422.
    """

    model_config = ConfigDict(extra="forbid")

    payload: Annotated[
        str,
        Field(
            min_length=1,
            max_length=MAX_ENCRYPTED_PAYLOAD_BYTES * 2,
            description=(
                "Base64-encoded AES-GCM-256 envelope "
                "(nonce||ciphertext||tag)"
            ),
        ),
    ]


class QueryExecutionRecord(BaseModel):
    """The plaintext execution record INSIDE the encrypted response envelope.

    Carries exactly what the Rust engine produced — the halo2 proof bytes
    plus the three public inputs (H_doc, H_prompt, H_out as 32-byte LE
    field representations, hex-encoded) — plus honest timing metadata. No
    fabricated answer text: the deterministic symbolic engine's current
    output IS the proof binding the hashes; a natural-language answer
    layer, if a later phase adds one, extends this record.
    """

    model_config = ConfigDict(extra="forbid")

    service: str = Field(description="Enclave service name")
    version: str = Field(description="API version")
    timestamp: str = Field(description="ISO-8601 UTC completion time")
    proof: str = Field(description="halo2 proof bytes, base64-encoded")
    doc_hash: str = Field(description="H_doc — 64 lowercase hex")
    prompt_hash: str = Field(description="H_prompt — 64 lowercase hex")
    output_hash: str = Field(description="H_out — 64 lowercase hex")
    latency_ms: float = Field(
        ge=0, description="Full pipeline wall time (decrypt to prove), ms"
    )


class EncryptedQueryResponse(BaseModel):
    """The enclave's reply: the execution record, AES-GCM-256 encrypted.

    The blind proxy forwards only ciphertext (blueprint: the enclave is a
    bidirectional secure gateway — Prompt 072). The response envelope is
    bound to the `/v1/query` context via composed AAD, so it cannot be
    decrypted under a different endpoint/session context.
    """

    model_config = ConfigDict(extra="forbid")

    envelope: str = Field(
        description=(
            "Base64 of AES-GCM-256(QueryExecutionRecord) for the "
            "/v1/query context"
        )
    )


class ProblemDetail(Exception):
    """Structured RFC 7807 error raised by handlers; rendered as a JSON
    Problem Details document (research + 077 cross-check endorsed)."""

    def __init__(self, status_code: int, title: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.title = title
        self.detail = detail


def _decode_envelope_base64(payload: str) -> bytes:
    """Strict base64 decode accepting BOTH the standard and URL-safe
    alphabets (Web Crypto clients may emit either), padding optional.

    URL-safe chars are normalized to the standard alphabet, then a single
    `validate=True` decode rejects any stray character — a corrupted
    envelope must fail, never silently mis-decode.
    """
    s = payload.strip()
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("payload is not valid base64") from exc


def _map_engine_error(message: str) -> tuple[int, str]:
    """Map processor/Rust-engine failures to HTTP semantics (never a panic,
    never a silent fallback).

    CONTRACT NOTE: the mapping substrings mirror the exact RuntimeError
    messages raised by `processor.py` (authentication tag mismatch /
    key not set / wheel not installed). If processor ever raises typed
    exceptions instead, update this mapping at the same time — tracked
    follow-up.
    """
    if "authentication tag mismatch" in message:
        return status.HTTP_401_UNAUTHORIZED, "authentication_failed"
    if "not set" in message or "wheel is not installed" in message:
        return status.HTTP_503_SERVICE_UNAVAILABLE, "enclave_not_configured"
    return status.HTTP_400_BAD_REQUEST, "query_failed"


def _network_status_to_dict(obj: Any) -> dict[str, Any]:
    """Serialize the connector's NetworkStatus result for the health body."""
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return {"value": str(obj)}


def _new_attestation_engine() -> AttestationEngine:
    """Construct the attestation engine with the configured contact points."""
    return AttestationEngine(
        endpoint=_ATTESTATION_ENDPOINT,
        intel_endpoint=_INTEL_ATTESTATION_ENDPOINT,
        socket_path=_TEESERVER_SOCKET,
    )


def _shape_intel_status(
    intel: IntelAttestationToken | None,
) -> IntelAttestationStatus | None:
    """Shape a validated ITA token into its response model — shared by the
    /attestation and /v1/attestation endpoints (code reuse, Prompt 088)."""
    if intel is None:
        return None
    return IntelAttestationStatus(
        attested=True,
        issuer=intel.issuer,
        hwmodel=intel.hwmodel or "",
        attester_tcb=list(intel.attester_tcb),
        tdx_quote=(
            dict(intel.tdx_quote) if isinstance(intel.tdx_quote, dict) else None
        ),
        policy_ids_matched=list(intel.policy_ids_matched),
        policy_ids_unmatched=list(intel.policy_ids_unmatched),
        token_issued_at=intel.issued_at,
    )


async def _check_attestation_dependency() -> dict[str, Any]:
    """Bounded, best-effort vTPM attestation status for /health.

    Liveness semantics (research + Prompt 077 cross-check): a missing or
    unreachable tee server does NOT 503 the probe — the body reports
    ``unavailable`` while the process stays 200. The /attestation endpoint
    (not /health) is the fail-closed authority and returns 503 there.
    """
    try:
        task = asyncio.create_task(_new_attestation_engine().fetch_token())
        try:
            token = await asyncio.wait_for(
                asyncio.shield(task), timeout=ATTESTATION_HEALTH_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass  # cancelled; nothing to clean up (stateless fetch)
            return {
                "status": "unavailable",
                "attested": False,
                "detail": (
                    f"attestation check timed out after "
                    f"{ATTESTATION_HEALTH_TIMEOUT_S}s"
                ),
            }
        return {
            "status": "attested",
            "attested": True,
            # Prompt 086 followup: the CEL identity gate (assertion.swname
            # == 'CONFIDENTIAL_SPACE') reported explicitly — the token the
            # engine validated carries it by construction, but the probe
            # surfaces the predicate result so orchestrators see it.
            "confidential_space": verify_confidential_space_claims(token.claims),
            "swname": token.swname,
            "hardware": token.hardware,
            "image_digest": token.image_digest,
        }
    except AttestationError as exc:
        return {
            "status": "unavailable",
            "attested": False,
            "detail": type(exc).__name__,
        }
    except Exception as exc:  # defensive: never crash the probe
        return {
            "status": "unavailable",
            "attested": False,
            "detail": type(exc).__name__,
        }


def _attestation_required() -> bool:
    """Whether /v1/query is gated on hardware attestation (production flag).

    Env: ``ENCLAVE_REQUIRE_ATTESTATION=1/true/yes``. Default OFF so local
    development and the Docker smoke image can run queries without a tee
    server; in the Confidential Space deployment the operator sets it to
    enforce the blueprint's "denies payload decryption key load" rule at
    the API layer. Read per-request (not at import) so the flag is
    trivially testable and togglable in test tooling.
    """
    return (
        os.environ.get("ENCLAVE_REQUIRE_ATTESTATION", "0").strip().lower()
        in ("1", "true", "yes")
    )


async def _check_rpc_dependency() -> dict[str, Any]:
    """Live Coston2 liveness check with a HARD bound so /health never hangs.

    The RPC is NOT on the query hot path (query = decrypt + Rust engine),
    so an RPC outage degrades the report but must never block or fail the
    probe (research + cross-check: do not 503 a liveness probe for an
    external dependency).
    """
    try:
        from src.flare_client.connector import FlareCoston2Client
    except Exception as exc:  # pragma: no cover — connector always importable
        return {
            "status": "unavailable",
            "detail": f"connector import failed: {type(exc).__name__}",
        }
    client = None
    try:
        client = FlareCoston2Client()
        # Shield the liveness task from wait_for's cancellation so that on
        # timeout WE cancel it explicitly and let its aiohttp session be
        # closed cleanly (no orphaned "Unclosed client session" at exit).
        task = asyncio.create_task(client.liveness())
        try:
            result = await asyncio.wait_for(
                asyncio.shield(task), timeout=RPC_HEALTH_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass  # cancelled; cleanup happens in the finally below
            return {
                "status": "unreachable",
                "detail": f"liveness check timed out after {RPC_HEALTH_TIMEOUT_S}s",
            }
        return {"status": "connected", "detail": _network_status_to_dict(result)}
    except Exception as exc:
        return {"status": "unreachable", "detail": type(exc).__name__}
    finally:
        if client is not None:
            await client.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """One-time boot setup (research + 077 cross-check: TEE fail-fast).

    Missing secrets or a missing engine wheel REFUSE to boot — in a TEE
    there is no operator to fix it later, so the container fails and
    restarts with correct configuration (fail-closed, matches config.py's
    zero-defaults policy from Prompt 076).
    """
    settings = get_settings()  # raises SecretMissingError if keys are absent
    try:
        import indexer_rs  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "indexer_rs engine wheel is not installed; build it with "
            "`maturin build --release --features python` (Prompt 054/060)"
        ) from exc
    app.state.settings = settings
    app.state.engine_ready = True
    # Prompt 088: the background-refreshed attestation state cache backing
    # GET /v1/attestation. Established at boot (the loop's first iteration
    # refreshes immediately), renewed before expiry (REFRESH_MARGIN_FRACTION
    # of the token lifetime), and fail-closed: while no valid state exists
    # the endpoint 503s. A still-valid state survives transient refresh
    # hiccups (it only expires via its own exp claim). Cancelled cleanly on
    # teardown so no dangling task outlives the event loop.
    attestation_stop = asyncio.Event()
    attestation_cache = AttestationStateCache(_new_attestation_engine())
    refresh_task = asyncio.create_task(
        attestation_cache.run_refresh_loop(attestation_stop)
    )
    app.state.attestation_cache = attestation_cache
    yield
    # Teardown: the query path constructs per-request cipher instances and
    # scrubs their keys in `finally`; nothing secret is held on app.state.
    attestation_stop.set()
    refresh_task.cancel()
    try:
        await refresh_task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title=APP_NAME,
    version="0.1.0",
    description=(
        "Secure enclave gateway: TLS-only ingress, restricted CORS, strict "
        "payload validation. /health liveness probe, /v1/query "
        "(encrypted-payload verifiable queries), /attestation (hardware "
        "vTPM attestation, fail-closed 503) and /v1/attestation (current "
        "attestation state snapshot, Prompt 088) are live."
    ),
    lifespan=lifespan,
)


@app.exception_handler(ProblemDetail)
async def _problem_detail_handler(
    request: Request, exc: ProblemDetail
) -> JSONResponse:
    """Render RFC 7807 Problem Details for structured enclave errors."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "type": "about:blank",
            "title": exc.title,
            "status": exc.status_code,
            "detail": exc.detail,
        },
    )

# Middleware order note (Starlette wraps in reverse): the LAST add_middleware
# call is the OUTERMOST. TLS/payload enforcement must be outermost, so it is
# registered last. The Prompt 096 attestation gate sits INSIDE the TLS layer
# (a non-TLS request is 426'd before the gate runs — cheapest check first)
# but OUTSIDE CORS/route logic, gating exactly POST /v1/query on the cached
# attestation state.
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,  # explicit allowlist, never "*"
    allow_credentials=True,
    # NOTE: `X-Forwarded-Proto`/`Forwarded` are deliberately NOT in
    # allow_headers: they are proxy-set headers, and letting browsers send
    # them cross-origin would widen the spoofing surface of the TLS check
    # (a direct plain-HTTP client could fake `X-Forwarded-Proto: https` to
    # bypass the 426). The TLS-terminating proxy MUST overwrite these
    # headers on ingress.
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
app.add_middleware(AttestationGateMiddleware)
app.add_middleware(TlsAndPayloadValidationMiddleware)


@app.get("/health")
async def health() -> JSONResponse:
    """Liveness probe (Prompt 077) for the container HEALTHCHECK and load
    balancers.

    Liveness semantics per research + cross-check: a degraded external
    dependency (Coston2 RPC) does NOT 503 — restarting the container
    cannot fix a testnet hiccup, so 200 is returned whenever the process is
    alive.    The body carries the RPC + vTPM attestation dependency status and a
    secret-free config snapshot so orchestrators see exactly what is
    degraded (the /attestation endpoint is the fail-closed 503 authority;
    /health only reports).
    """
    rpc = await _check_rpc_dependency()
    attestation = await _check_attestation_dependency()
    settings = getattr(app.state, "settings", None)
    if settings is not None:
        config_snapshot = settings.get_public_snapshot()
    else:  # boot fail-fast makes this unreachable; defensive only
        config_snapshot = {"status": "unavailable"}
    engine_ready = bool(getattr(app.state, "engine_ready", False))
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "healthy" if rpc["status"] == "connected" else "degraded",
            "service": APP_NAME,
            "version": app.version,
            "uptime_seconds": round(time.monotonic() - _BOOT_TIME, 2),
            "engine_ready": engine_ready,
            "config": config_snapshot,
            "dependencies": {
                "rpc": rpc,
                "attestation": attestation,
                "engine": {"status": "ready" if engine_ready else "unavailable"},
            },
        },
    )


@app.get("/attestation", response_model=AttestationStatusResponse)
async def attestation_status() -> AttestationStatusResponse:
    """Fetch REAL hardware measurements from the local vTPM tee server.

    The fail-closed attestation authority (blueprint SRE table: "vTPM Token
    Fetch Timeout -> FastAPI Gateway returns HTTP 503 Service Unavailable;
    denies payload decryption key load"). Uses the Prompt 083 fallback flow:
    on Intel TDX the endpoint ALSO fetches and validates the Intel Trust
    Authority token (independent third-party verifier) and surfaces its
    measurements — the ITA fetch is mandatory on TDX, so any failure there
    also 503s. On AMD / unknown hardware only the primary Google
    attestation is reported. The enclave never claims attestation it
    cannot prove, and never falls back to a degraded result.
    """
    engine = _new_attestation_engine()
    try:
        result = await asyncio.wait_for(
            engine.fetch_token_with_fallback(), timeout=ATTESTATION_FETCH_TIMEOUT_S
        )
    except asyncio.TimeoutError:
        raise ProblemDetail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "attestation_unavailable",
            f"attestation fetch exceeded {ATTESTATION_FETCH_TIMEOUT_S}s (fail closed)",
        )
    except AttestationError as exc:
        raise ProblemDetail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "attestation_unavailable",
            str(exc),
        ) from exc
    response = AttestationStatusResponse(**result.primary.to_status_response())
    response.intel = _shape_intel_status(result.intel)
    return response


@app.get("/v1/attestation", response_model=AttestationStateResponse)
async def v1_attestation_state() -> AttestationStateResponse:
    """Current enclave hardware-attestation STATE (Prompt 088).

    Read-only snapshot served from the background-refreshed attestation
    cache (the production state-snapshot pattern: no blocking hardware
    quote per call — no vTPM rate-limit pressure, instant responses).
    The raw vTPM OIDC JWT is deliberately NOT returned (blind-proxy best
    practice); the token is isolated to ``POST /v1/attestation-proof``
    for the on-chain relying party.

    Fail-closed: 503 when the enclave cannot PROVE attestation (state not
    yet established or the held token expired). Never 200 with
    ``attested=false`` — load balancers and blind proxies route on the
    status code and must evict an unproven node. (Unlike the /attestation
    authority, which deep-checks a FRESH quote per call, this endpoint
    reads the cached state; a transient refresh hiccup keeps the last
    still-valid token.)
    """
    cache: AttestationStateCache | None = getattr(
        app.state, "attestation_cache", None
    )
    if cache is None:
        # Fail closed (consistent with /health's getattr style): the cache is
        # always installed by lifespan, so this is defensive only.
        raise ProblemDetail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "attestation_unavailable",
            "attestation cache not initialized (lifespan did not run)",
        )
    try:
        state = cache.snapshot()
    except AttestationError as exc:
        raise ProblemDetail(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "attestation_unavailable",
            str(exc),
        ) from exc
    primary = state.primary
    validity: int | None = None
    if primary.expires_at is not None:
        validity = max(
            0, int((primary.expires_at - datetime.datetime.now(timezone.utc)).total_seconds())
        )
    return AttestationStateResponse(
        attested=True,
        swname=primary.swname,
        image_digest=primary.image_digest,
        instance_id=primary.instance_id,
        hardware=primary.hardware,
        token_issued_at=primary.issued_at,
        token_expires_at=primary.expires_at,
        validity_seconds_remaining=validity,
        confidential_space=verify_confidential_space_claims(primary.claims),
        intel=_shape_intel_status(state.intel),
    )


@app.post("/v1/attestation-proof", response_model=AttestationProofResponse)
async def v1_attestation_proof(
    body: EncryptedQueryRequest,
) -> AttestationProofResponse:
    """Generate the combined hardware + execution attestation proof (Prompt
    087).

    The client posts the SAME encrypted envelope contract as `/v1/query`
    (``{"document", "prompt"}`` under ``ENCLAVE_PAYLOAD_KEY``); the enclave
    decrypts it in RAM, runs the REAL Rust symbolic engine over the
    plaintext, and binds the vTPM attestation token + attested image digest
    + ZK proof into one record with a recomputable binding hash.

    Fail-closed: any attestation/engine failure returns a structured 503
    (the token fetch raises the typed AttestationError →
    ``attestation_unavailable``; a missing wheel → ``enclave_not_configured``);
    payload framing errors 400; decryption auth failures 401. The raw
    vTPM token in the response is the relying-party artifact for the later
    on-chain verification phase — it is returned intentionally (the blind
    proxy forwards the record for settlement), never logged.
    """
    try:
        envelope = _decode_envelope_base64(body.payload)
    except ValueError as exc:
        raise ProblemDetail(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "payload is not valid base64",
        ) from exc

    cipher = None
    try:
        try:
            cipher = ClientPayloadCipher()
        except PayloadKeyError as exc:
            # Missing ENCLAVE_PAYLOAD_KEY: fail closed 503 (blueprint:
            # "denies payload decryption key load"), same semantic the
            # /v1/query path maps via _map_engine_error.
            raise ProblemDetail(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "enclave_not_configured",
                str(exc),
            ) from exc
        try:
            client_payload = cipher.decrypt_payload(envelope)
        except (PayloadFormatError, DecryptionError) as exc:
            raise ProblemDetail(
                status.HTTP_401_UNAUTHORIZED
                if isinstance(exc, DecryptionError)
                else status.HTTP_400_BAD_REQUEST,
                "authentication_failed"
                if isinstance(exc, DecryptionError)
                else "invalid_envelope",
                str(exc),
            ) from exc
        try:
            proof = await asyncio.wait_for(
                _new_attestation_engine().generate_attestation_proof(
                    client_payload.document, client_payload.prompt
                ),
                timeout=ATTESTATION_FETCH_TIMEOUT_S * 2,
            )
        except asyncio.TimeoutError:
            raise ProblemDetail(
                status.HTTP_504_GATEWAY_TIMEOUT,
                "attestation_proof_timeout",
                "attestation proof generation exceeded the enclave deadline",
            )
        except AttestationError as exc:
            raise ProblemDetail(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "attestation_unavailable",
                str(exc),
            ) from exc
        except RuntimeError as exc:
            code, title = _map_engine_error(str(exc))
            raise ProblemDetail(code, title, str(exc)) from exc
        except Exception as exc:  # never leak internals; never panic
            _logger.exception("v1/attestation-proof unexpected failure")
            raise ProblemDetail(
                status.HTTP_500_INTERNAL_SERVER_ERROR,
                "internal_error",
                "unexpected enclave failure",
            ) from exc
        finally:
            client_payload.scrub()  # zero the plaintext buffer (Prompt 067)
    finally:
        if cipher is not None:
            cipher.scrub()  # zero the held key after use

    record = proof.to_record()
    return AttestationProofResponse(
        attested=record["attested"],
        swname=record["swname"],
        image_digest=record["image_digest"],
        hardware=record["hardware"],
        zk_proof=record["zk_proof"],
        public_inputs=record["public_inputs"],
        binding_hash=record["binding_hash"],
        token=proof.raw_token,
    )


@app.post("/v1/query", response_model=EncryptedQueryResponse)
async def v1_query(
    body: EncryptedQueryRequest,
    processor: EphemeralProcessor = Depends(get_ephemeral_processor),
) -> EncryptedQueryResponse:
    """Execute a verifiable query against the enclave corpus (Prompt 077).

    1. Decode the base64 AES-GCM-256 envelope (standard or URL-safe).
    2. Run the FULL RAM-only pipeline in a worker thread: decrypt with
       `ENCLAVE_PAYLOAD_KEY`, strictly validate `{document, prompt}`,
       execute the REAL Rust symbolic engine (`indexer_rs.parse_and_prove`,
       GIL released) — deterministic, zero disk writes, every sensitive
       buffer zeroed after use (Prompt 067). Hard deadline `QUERY_TIMEOUT_S`.
    3. Encrypt the execution record back for the blind proxy, bound to the
       `/v1/query` context via composed AAD (Prompt 072 bidirectional
       gateway).

    Errors are structured RFC 7807 Problem Details: base64/framing errors
    400, cryptographic authentication failure 401, engine misconfiguration
    503, attestation gate 503 ``attestation_required`` (enforced by the
    Prompt 096 ``AttestationGateMiddleware`` when
    ENCLAVE_REQUIRE_ATTESTATION=1 — the handler itself no longer fetches a
    fresh token per request; the middleware gates on the cached state),
    deadline expiry 504. The processor dependency is destroyed (all buffers
    zeroed) after the response, on success AND on exception.
    """
    try:
        envelope = _decode_envelope_base64(body.payload)
    except ValueError as exc:
        raise ProblemDetail(
            status.HTTP_400_BAD_REQUEST,
            "invalid_request",
            "payload is not valid base64",
        ) from exc

    # Defense-in-depth cap on the DECODED envelope. With the default
    # ENCLAVE_MAX_PAYLOAD_BYTES=1 MiB, the middleware's wire-body cap is the
    # governing bound (b64 inflates ~1.33x); this 413 only becomes reachable
    # if an operator raises the middleware cap above ~5.6 MiB.
    if len(envelope) > MAX_ENCRYPTED_PAYLOAD_BYTES:
        raise ProblemDetail(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            "payload_too_large",
            f"envelope of {len(envelope)} bytes exceeds the "
            f"{MAX_ENCRYPTED_PAYLOAD_BYTES}-byte cap",
        )

    try:
        # stdlib bounded-offload pattern: run the CPU-bound (GIL-releasing)
        # pipeline in a worker thread and enforce a hard response deadline.
        # (asyncio.wait_for + asyncio.to_thread — the research's own health
        # check used asyncio.wait_for; avoids a broken anyio.fail_after
        # resolution observed in this venv.)
        result = await asyncio.wait_for(
            asyncio.to_thread(processor.execute_query, envelope),
            timeout=QUERY_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        raise ProblemDetail(
            status.HTTP_504_GATEWAY_TIMEOUT,
            "query_timeout",
            f"query exceeded the {QUERY_TIMEOUT_S}s enclave deadline",
        )
    except ValueError as exc:
        raise ProblemDetail(
            status.HTTP_400_BAD_REQUEST, "invalid_envelope", str(exc)
        ) from exc
    except RuntimeError as exc:
        code, title = _map_engine_error(str(exc))
        raise ProblemDetail(code, title, str(exc)) from exc
    except Exception as exc:  # never leak internals; never panic
        # The traceback goes to the enclave log (SRE), the client sees only
        # the structured 500 — no internals, no plaintext, no key material.
        _logger.exception("v1/query unexpected failure")
        raise ProblemDetail(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "unexpected enclave failure",
        ) from exc

    record = QueryExecutionRecord(
        service=APP_NAME,
        version=app.version,
        timestamp=datetime.datetime.now(timezone.utc).isoformat(),
        proof=base64.b64encode(result.proof).decode("ascii"),
        doc_hash=result.doc_hash.hex(),
        prompt_hash=result.prompt_hash.hex(),
        output_hash=result.output_hash.hex(),
        latency_ms=round(result.latency_ms, 3),
    )

    cipher = ClientPayloadCipher()
    try:
        response_envelope = cipher.encrypt_response(
            record.model_dump_json().encode("utf-8"), context=QUERY_CONTEXT_AAD
        )
    finally:
        cipher.scrub()  # zero the held key after use (Prompt 067 pattern)

    return EncryptedQueryResponse(
        envelope=base64.b64encode(response_envelope).decode("ascii")
    )


@app.get("/")
async def root() -> dict:
    """Service metadata (no business data, no secrets)."""
    return {
        "service": APP_NAME,
        "status": "operational",
        "tls_enforced": True,
        "cors_origins_configured": len(_CORS_ORIGINS),
        "max_payload_bytes": MAX_PAYLOAD_BYTES,
    }


# Local development convenience: python -m src.main
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("src.main:app", host="0.0.0.0", port=8000)

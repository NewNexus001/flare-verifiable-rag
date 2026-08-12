"""Prompt 083 followup + Prompt 096 — tests for the /v1/query attestation
middleware gate.

The full 503 flow through the REAL HTTP surface with the real engine is
proven by ``.tools/083_verify.py`` (TestClient + real tee server + real
wheel). This module pins, in the permanent suite (no wheel needed):

* the pure flag-parsing contract of ``src.main._attestation_required``;
* the Prompt 096 ``AttestationGateMiddleware`` contract — built over a
  minimal FastAPI app with a REAL ``AttestationStateCache`` backed by a
  REAL local tee server serving genuinely HS256-signed JWTs:

  * flag OFF → pass-through even with a never-established cache;
  * flag ON + never-established state → RFC 7807 503 ``attestation_required``;
  * flag ON + valid established state → pass-through (200);
  * flag ON + REALLY expired state → 503 (wall-clock wait, real expiry);
  * ``/health`` and ``/v1/attestation`` stay EXEMPT while ``/v1/query``
    is blocked (orchestrators can always diagnose an unproven node);
  * only ``POST /v1/query`` is gated — other paths pass;
  * missing cache on ``app.state`` (lifespan not run) → fail-closed 503.

The ``assert_no_disk_io`` autouse fixture (conftest) applies here too.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import http.server
import json
import secrets
import socket
import threading
import time
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.crypto.attestation import (
    AttestationEngine,
    AttestationServiceUnavailableError,
    AttestationStateCache,
    AttestationWithIntel,
    DEFAULT_AUDIENCE,
)
from src.main import AttestationGateMiddleware, _attestation_required

TRUTHY = ["1", "true", "TRUE", "yes", " Yes ", " 1 "]
FALSY = ["0", "false", "no", "", "banana", "2", "Trueish"]


@pytest.mark.parametrize("value", TRUTHY)
def test_gate_flag_truthy(monkeypatch, value: str):
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", value)
    assert _attestation_required() is True


@pytest.mark.parametrize("value", FALSY)
def test_gate_flag_falsy(monkeypatch, value: str):
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", value)
    assert _attestation_required() is False


def test_gate_flag_default_off(monkeypatch):
    monkeypatch.delenv("ENCLAVE_REQUIRE_ATTESTATION", raising=False)
    assert _attestation_required() is False


# ---------------------------------------------------------------------------
# Prompt 096 — AttestationGateMiddleware (REAL tee server, real signed JWT)
# ---------------------------------------------------------------------------

JWT_SECRET = secrets.token_bytes(32)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(claims: dict[str, Any]) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = hmac.new(JWT_SECRET, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def make_claims(
    *,
    audience: str = DEFAULT_AUDIENCE,
    nonce: str | None = "n1",
    exp_offset: float = 3600.0,
    **extra: Any,
) -> dict[str, Any]:
    """A REAL Confidential Space claim set (Prompt 085 shape — image_digest
    NESTED at submods.container.image_digest, instance_id at submods.gce)."""
    now = time.time()
    claims: dict[str, Any] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "sub": "projects/flare-prod/zones/us-central1-a/instances/enclave-1",
        "aud": audience,
        "iat": int(now - 5),
        "exp": int(now + exp_offset),
        "jti": secrets.token_hex(16),
        "swname": "CONFIDENTIAL_SPACE",
        "swversion": ["240500"],
        "hwmodel": "GCP_AMD_SEV",
        "submods": {
            "container": {
                "image_digest": "sha256:" + "ab" * 32,
                "image_id": "sha256:" + "cd" * 32,
                "restart_policy": "Always",
            },
            "gce": {
                "instance_id": "3507932791508176595",
                "project_id": "flare-prod",
                "zone": "us-central1-a",
            },
        },
        "dbgstat": "disabled-since-boot",
        "attester_tcb": ["AMD-SEV-SNP"],
        "google_service_accounts": ["sa@flare.iam.gserviceaccount.com"],
    }
    if nonce is not None:
        claims["eat_nonce"] = nonce
    claims.update(extra)
    return claims


def make_server(
    exp_offset: float = 3600.0,
) -> tuple[http.server.HTTPServer, str]:
    """A REAL local tee server echoing the request nonce/audience into a
    signed Confidential Space JWT; returns (server, engine_url)."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence
            pass

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            req = json.loads(body)
            claims = make_claims(
                audience=req["audience"],
                nonce=req["nonces"][0],
                exp_offset=exp_offset,
            )
            payload = sign_hs256(claims).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/v1/token"
    return server, url


def dead_url() -> str:
    """A URL with nothing listening (connection refused) — real fail-closed."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}/v1/token"


def run(coro):
    return asyncio.run(coro)


def make_gate_app(cache: AttestationStateCache | None) -> FastAPI:
    """A minimal FastAPI app with ONLY the Prompt 096 gate middleware plus
    stub routes — isolates the middleware (no TLS/CORS/wheel needed)."""
    app = FastAPI()
    app.state.attestation_cache = cache
    app.add_middleware(AttestationGateMiddleware)

    @app.post("/v1/query")
    async def query() -> dict:
        return {"ok": "query-executed"}

    @app.get("/health")
    async def health() -> dict:
        return {"ok": "healthy"}

    @app.get("/v1/attestation")
    async def attestation() -> dict:
        return {"ok": "attestation-state"}

    @app.post("/other")
    async def other() -> dict:
        return {"ok": "other"}

    return app


def established_cache(url: str) -> AttestationStateCache:
    """A REAL cache with REAL established state (fresh, unexpired token)."""
    cache = AttestationStateCache(AttestationEngine(endpoint=url, nonces=["n1"]))
    result = run(cache.refresh())
    assert isinstance(result, AttestationWithIntel)
    return cache


# --- flag OFF: pass-through even with a never-established cache -----------


def test_gate_off_passes_through_with_never_established_cache(monkeypatch):
    monkeypatch.delenv("ENCLAVE_REQUIRE_ATTESTATION", raising=False)
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))
    with TestClient(make_gate_app(cache)) as client:
        r = client.post("/v1/query", json={"x": 1})
        assert r.status_code == 200
        assert r.json() == {"ok": "query-executed"}


def test_gate_off_passes_through_without_cache_attribute(monkeypatch):
    monkeypatch.delenv("ENCLAVE_REQUIRE_ATTESTATION", raising=False)
    app = FastAPI()
    app.add_middleware(AttestationGateMiddleware)

    @app.post("/v1/query")
    async def query() -> dict:
        return {"ok": "query-executed"}

    with TestClient(app) as client:
        r = client.post("/v1/query", json={"x": 1})
        assert r.status_code == 200
        assert r.json() == {"ok": "query-executed"}


# --- flag ON: fail-closed matrix ------------------------------------------


def test_gate_on_never_established_returns_503_rfc7807(monkeypatch):
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))
    with pytest.raises(AttestationServiceUnavailableError):
        cache.snapshot()  # sanity: never-established really raises
    with TestClient(make_gate_app(cache)) as client:
        r = client.post("/v1/query", json={"x": 1})
        assert r.status_code == 503
        body = r.json()
        assert body["title"] == "attestation_required"
        assert body["status"] == 503
        assert "attestation state not yet established" in body["detail"]
        assert r.headers.get("retry-after") == "10"


def test_gate_on_valid_state_passes(monkeypatch):
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    server, url = make_server()
    try:
        cache = established_cache(url)
        with TestClient(make_gate_app(cache)) as client:
            r = client.post("/v1/query", json={"x": 1})
            assert r.status_code == 200
            assert r.json() == {"ok": "query-executed"}
    finally:
        server.shutdown()
        server.server_close()


def test_gate_on_really_expired_state_returns_503(monkeypatch):
    """A token that parses VALID then REALLY expires (short exp, real
    wall-clock wait) must block the query — no stale attestation is ever
    used to authorize processing (the Prompt 088 expiry semantic)."""
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    server, url = make_server(exp_offset=3.0)  # expires ~3s from now
    try:
        cache = established_cache(url)
        cache.snapshot()  # valid right after refresh (3s window — no race)
        time.sleep(3.4)  # let exp pass in REAL time
        with pytest.raises(AttestationServiceUnavailableError, match="expired"):
            cache.snapshot()  # sanity: the cache really expired
        with TestClient(make_gate_app(cache)) as client:
            r = client.post("/v1/query", json={"x": 1})
            assert r.status_code == 503
            assert r.json()["title"] == "attestation_required"
    finally:
        server.shutdown()
        server.server_close()


def test_gate_on_missing_cache_fails_closed(monkeypatch):
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    app = FastAPI()
    app.add_middleware(AttestationGateMiddleware)  # NO cache on app.state

    @app.post("/v1/query")
    async def query() -> dict:
        return {"ok": "query-executed"}

    with TestClient(app) as client:
        r = client.post("/v1/query", json={"x": 1})
        assert r.status_code == 503
        body = r.json()
        assert body["title"] == "attestation_required"
        assert "not initialized" in body["detail"]


# --- exemptions + scoping --------------------------------------------------


def test_gate_blocks_query_but_exempts_health_and_state(monkeypatch):
    """With attestation invalid, /v1/query is 503 while /health and
    /v1/attestation stay readable — orchestrators must always be able to
    diagnose an unproven node (research: never trap the health probe)."""
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))
    with TestClient(make_gate_app(cache)) as client:
        assert client.post("/v1/query", json={"x": 1}).status_code == 503
        assert client.get("/health").status_code == 200
        assert client.get("/health").json() == {"ok": "healthy"}
        assert client.get("/v1/attestation").status_code == 200
        assert client.post("/other", json={"x": 1}).status_code == 200


def test_gate_only_blocks_post_on_query_path(monkeypatch):
    """GET /v1/query is not gated (the sensitive operation is POST); only
    the exact path is matched — no prefix or sibling paths."""
    monkeypatch.setenv("ENCLAVE_REQUIRE_ATTESTATION", "1")
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))
    with TestClient(make_gate_app(cache)) as client:
        assert client.post("/v1/query", json={"x": 1}).status_code == 503
        assert client.get("/v1/query").status_code == 405  # method not allowed
        assert client.post("/v1/query/extra", json={"x": 1}).status_code == 404

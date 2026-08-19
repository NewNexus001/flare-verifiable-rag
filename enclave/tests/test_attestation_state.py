"""Prompt 088 — permanent unit tests for the current-attestation state cache.

Targets ``src.crypto.attestation.AttestationStateCache``: the
background-refreshed source of truth behind ``GET /v1/attestation``. Per
the user-pro-verified production research (GCP Confidential Space / Nitro /
Azure MAA state-snapshot pattern), the endpoint must serve an
instantaneous derived-metadata snapshot — never a blocking hardware quote
per call — and must FAIL CLOSED (HTTP 503 semantic) when attestation
cannot be proven, never ``200`` with ``attested=false``.

What is proven, and how (all REAL):

* **Real transport** — a REAL local ``http.server`` on 127.0.0.1 answers
  the engine's POST and returns a genuinely HS256-signed JWT (RFC 7518,
  CSPRNG key). Nothing is monkeypatched on the fetch path.
* **Fail-closed establishment** — before any refresh succeeds, ``snapshot``
  raises :class:`AttestationServiceUnavailableError` (the 503 semantic).
* **Real expiry** — a token parsed valid that then REALLY expires (short
  ``exp``, real wall-clock wait) makes ``snapshot`` raise; a valid token
  is never downgraded by a refresh hiccup (failed refresh keeps the last
  valid state).
* **Background loop** — ``run_refresh_loop`` establishes state at boot and
  never crashes when the tee server is down (retries, records
  ``last_error``, stays fail-closed).

The ``assert_no_disk_io`` autouse fixture (conftest) applies: the RAM-only
invariant must hold even while the local tee server binds sockets.

NOTE: the full HTTP surface (``GET /v1/attestation`` through FastAPI +
lifespan, which needs the ``indexer_rs`` wheel and env keys) is covered by
``.tools/083_verify.py`` and ``.tools/docker_smoke.py`` — the permanent
suite convention is to keep wheel/app-lifespan logic in the harnesses.
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

from src.crypto.attestation import (
    REFRESH_MARGIN_FRACTION,
    STATE_MAX_INTERVAL_S,
    STATE_POLL_INTERVAL_S,
    AttestationEngine,
    AttestationServiceUnavailableError,
    AttestationStateCache,
    AttestationWithIntel,
    DEFAULT_AUDIENCE,
)

# --- REAL JWT fixture machinery (genuine HS256 signatures) ---------------

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
    swname: str = "CONFIDENTIAL_SPACE",
    image_digest: str = "sha256:" + "ab" * 32,
    instance_id: str | None = "3507932791508176595",
    hwmodel: str = "GCP_AMD_SEV",
    exp_offset: float = 3600.0,
    iat_offset: float = -5.0,
    **extra: Any,
) -> dict[str, Any]:
    """A REAL Confidential Space claim set (Prompt 085 research): image_digest
    NESTED at submods.container.image_digest, instance_id at submods.gce."""
    now = time.time()
    submods: dict[str, Any] = {
        "container": {
            "image_digest": image_digest,
            "image_id": "sha256:" + "cd" * 32,
            "restart_policy": "Always",
        }
    }
    if instance_id is not None:
        submods["gce"] = {
            "instance_id": instance_id,
            "project_id": "flare-prod",
            "zone": "us-central1-a",
        }
    claims: dict[str, Any] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "sub": "projects/flare-prod/zones/us-central1-a/instances/enclave-1",
        "aud": audience,
        "iat": int(now + iat_offset),
        "exp": int(now + exp_offset),
        "jti": secrets.token_hex(16),
        "swname": swname,
        "swversion": ["240500"],
        "hwmodel": hwmodel,
        "submods": submods,
        "dbgstat": "disabled-since-boot",
        "attester_tcb": ["AMD-SEV-SNP"],
        "google_service_accounts": ["sa@flare.iam.gserviceaccount.com"],
    }
    if nonce is not None:
        claims["eat_nonce"] = nonce
    claims.update(extra)
    return claims


def make_server() -> http.server.HTTPServer:
    """A REAL local tee server echoing the request nonce/audience into a
    signed Confidential Space JWT."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence
            pass

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            req = json.loads(body)
            claims = make_claims(audience=req["audience"], nonce=req["nonces"][0])
            payload = sign_hs256(claims).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def engine_url(server: http.server.HTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}/v1/token"


def dead_url() -> str:
    """A URL with nothing listening (connection refused) — real fail-closed."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return f"http://127.0.0.1:{port}/v1/token"


def run(coro):
    return asyncio.run(coro)


# --- scheduling constants (honest, documented) ----------------------------


def test_renewal_policy_constants_are_sane():
    assert 0.0 < REFRESH_MARGIN_FRACTION < 1.0
    assert STATE_POLL_INTERVAL_S > 0
    assert STATE_MAX_INTERVAL_S >= STATE_POLL_INTERVAL_S


# --- fail-closed establishment -------------------------------------------


def test_snapshot_before_any_refresh_fails_closed():
    cache = AttestationStateCache()
    with pytest.raises(AttestationServiceUnavailableError):
        cache.snapshot()  # never 200-with-attested=false; the 503 semantic


def test_seconds_until_refresh_without_state_is_zero():
    cache = AttestationStateCache()
    assert cache._seconds_until_refresh() == 0.0  # refresh immediately


# --- real fetch + snapshot ------------------------------------------------


def test_refresh_establishes_real_state_and_snapshot():
    server = make_server()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(server), nonces=["n1"])
        )
        result = run(cache.refresh())
        assert isinstance(result, AttestationWithIntel)
        assert result.primary.swname == "CONFIDENTIAL_SPACE"
        assert result.primary.hardware == "AMD SEV-SNP"
        assert result.intel is None  # AMD — no ITA fallback
        state = cache.snapshot()
        assert state is result
        assert cache.last_error is None
        # Everything the /v1/attestation endpoint needs is REAL token data.
        assert state.primary.issued_at is not None
        assert state.primary.expires_at is not None
        assert state.primary.image_digest.startswith("sha256:")
        assert state.primary.instance_id == "3507932791508176595"
    finally:
        server.shutdown()
        server.server_close()


def test_refresh_failure_records_error_and_keeps_last_valid_state():
    server = make_server()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(server), nonces=["n1"])
        )
        run(cache.refresh())  # established
        server.shutdown()
        server.server_close()  # tee server now DOWN
        with pytest.raises(AttestationServiceUnavailableError):
            run(cache.refresh())  # refresh hiccup — raises, keeps state
        assert cache.last_error is not None
        # A valid attestation is NEVER downgraded by a refresh hiccup —
        # it only expires via its own exp claim (production pattern).
        state = cache.snapshot()
        assert state.primary.swname == "CONFIDENTIAL_SPACE"
    finally:
        try:
            server.shutdown()
            server.server_close()
        except OSError:
            pass


def test_refresh_unreachable_endpoint_fails_closed():
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))
    with pytest.raises(AttestationServiceUnavailableError):
        run(cache.refresh())
    assert cache.last_error is not None


# --- real expiry -----------------------------------------------------------


def test_snapshot_rejects_state_that_really_expired():
    """A token that parses VALID then REALLY expires (short exp, wall-clock
    wait) must fail closed — no stale attestation is ever served."""

    class ShortExpiryHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            req = json.loads(body)
            claims = make_claims(
                audience=req["audience"],
                nonce=req["nonces"][0],
                exp_offset=3.0,  # expires ~3s from now (comfortable parse margin)
            )
            payload = sign_hs256(claims).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    short = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ShortExpiryHandler)
    threading.Thread(target=short.serve_forever, daemon=True).start()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(short), nonces=["n1"])
        )
        run(cache.refresh())
        cache.snapshot()  # valid right after refresh (3s window — no race)
        time.sleep(3.4)  # let exp pass in REAL time
        with pytest.raises(AttestationServiceUnavailableError, match="expired"):
            cache.snapshot()
    finally:
        short.shutdown()
        short.server_close()


def test_refresh_scheduling_is_due_before_expiry():
    """The renewal policy: refresh is due BEFORE the token expires (margin =
    REFRESH_MARGIN_FRACTION of the lifetime), so the cache never hands a
    proxy an about-to-expire state."""
    server = make_server()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(server), nonces=["n1"])
        )
        run(cache.refresh())
        remaining = cache._seconds_until_expiry()
        due = cache._seconds_until_refresh()
        assert remaining is not None and remaining > 0
        assert 0 < due < remaining  # strictly before expiry
    finally:
        server.shutdown()
        server.server_close()


# --- background refresh loop ------------------------------------------------


def test_run_refresh_loop_establishes_state_at_boot():
    server = make_server()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(server), nonces=["n1"])
        )

        async def drive() -> None:
            stop = asyncio.Event()
            task = asyncio.create_task(cache.run_refresh_loop(stop))
            await asyncio.sleep(0.3)  # first iteration refreshes immediately
            assert cache.snapshot().primary.swname == "CONFIDENTIAL_SPACE"
            stop.set()
            await task

        run(drive())
    finally:
        server.shutdown()
        server.server_close()


def test_run_refresh_loop_never_crashes_when_tee_down():
    cache = AttestationStateCache(AttestationEngine(endpoint=dead_url()))

    async def drive() -> None:
        stop = asyncio.Event()
        task = asyncio.create_task(cache.run_refresh_loop(stop))
        try:
            # Poll for the observable effect (threadpool round-trip latency is
            # nondeterministic under load) — real retry behavior, not a sleep.
            deadline = time.monotonic() + 5.0
            while cache.last_error is None and time.monotonic() < deadline:
                await asyncio.sleep(0.1)
            # Fail-closed: still no state, the failure is recorded, no crash.
            with pytest.raises(AttestationServiceUnavailableError):
                cache.snapshot()
            assert cache.last_error is not None
        finally:
            stop.set()
            await task

    run(drive())


def test_run_refresh_loop_keeps_valid_state_when_tee_dies():
    """The loop keeps serving the last VALID state while the tee server is
    down — the held token is unexpired, so the snapshot stays 200-eligible.
    (The failed-refresh-keeps-state path itself is proven directly by
    test_refresh_failure_records_error_and_keeps_last_valid_state; the loop
    only attempts renewal near the expiry margin, so no refresh fires inside
    this window — by design.)"""
    server = make_server()
    try:
        cache = AttestationStateCache(
            AttestationEngine(endpoint=engine_url(server), nonces=["n1"])
        )

        async def drive() -> None:
            stop = asyncio.Event()
            task = asyncio.create_task(cache.run_refresh_loop(stop))
            try:
                deadline = time.monotonic() + 5.0
                while True:
                    try:
                        state = cache.snapshot()
                        break
                    except AttestationServiceUnavailableError:
                        if time.monotonic() > deadline:
                            raise
                        await asyncio.sleep(0.1)
                assert state.primary.swname == "CONFIDENTIAL_SPACE"
                server.shutdown()
                server.server_close()  # tee DOWN mid-flight
                await asyncio.sleep(0.5)  # loop is alive, sleeping till renewal
                # Still fail-closed-safe AND still serving the valid state.
                assert cache.snapshot().primary.swname == "CONFIDENTIAL_SPACE"
            finally:
                stop.set()
                await task

        run(drive())
    finally:
        try:
            server.shutdown()
            server.server_close()
        except OSError:
            pass

"""Prompt 081/082 — permanent unit tests for the vTPM attestation engine.

Targets ``src.crypto.attestation``: the Confidential Space contract
(``POST http://localhost/v1/token`` with ``{audience, nonces,
token_type:"OIDC"}``), stdlib-only JWT parse/validation, the fail-closed
typed-error taxonomy, and the Prompt 082 ``fetch_vtpm_token()`` API.

What is proven, and how:

* **Real JWT fixtures** — every token is genuinely signed with HS256 (RFC
  7518) under a per-module CSPRNG key. The enclave does not verify
  signatures at fetch time (the relying party does), but no fixture is
  fabricated text: signatures are real.
* **Real transport** — a REAL local ``http.server`` on 127.0.0.1 answers
  the engine's POST, echoes the request nonce into ``eat_nonce``, and
  returns the signed JWT. Nothing is monkeypatched on the fetch path.
* **Validation matrix** — structure (segments/base64/JSON), temporal
  (exp/iat with clock skew), environment (swname), digest format, audience
  pinning, and nonce-echo anti-replay all enforced; every failure raises
  exactly the typed error (never a fallback, never a panic).
* **Fail-closed transport** — unreachable endpoint, empty body, and
  timeout all raise :class:`AttestationServiceUnavailableError`.
* **Prompt 082 API** — ``fetch_vtpm_token()`` (module-level and engine
  method) returns the RAW JWT string (transport only, no parsing).

The ``assert_no_disk_io`` autouse fixture from conftest.py applies here
too: the RAM-only invariant must hold even while the local tee server
binds sockets (server code never writes a file).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import time
from typing import Any, Callable

import pytest

from src.crypto import CryptoError
from src.crypto.attestation import (
    AttestationEngine,
    AttestationError,
    AttestationProof,
    AttestationServiceUnavailableError,
    AttestationToken,
    AttestationTokenError,
    AttestationWithIntel,
    DEFAULT_AUDIENCE,
    DEFAULT_TIMEOUT_S,
    EXPECTED_SWNAME,
    EXPECTED_TDX_HWMODEL,
    INTEL_TOKEN_ENDPOINT,
    ITA_OIDC_ISSUER,
    IntelAttestationToken,
    TEESERVER_SOCKET,
    UntrustedEnvironmentError,
    fetch_intel_token,
    fetch_vtpm_token,
    generate_attestation_proof,
    is_tdx_hardware,
    submit_attestation_to_flare,
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
    """A REAL Confidential Space claim set (Prompt 085 research):
    ``image_digest`` NESTED at ``submods.container.image_digest`` and
    ``instance_id`` NESTED at ``submods.gce.instance_id`` — never the fake
    top-level shape."""
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


def parse(claims: dict[str, Any], **kw: Any) -> AttestationToken:
    """Parse a signed fixture with the standard audience + nonce pinning."""
    return AttestationEngine.parse_token(
        sign_hs256(claims),
        expected_audience=kw.pop("expected_audience", DEFAULT_AUDIENCE),
        expected_nonces=kw.pop("expected_nonces", ("n1",)),
        **kw,
    )


# --- Parsing / validation matrix -----------------------------------------


def test_parse_valid_token_measurements():
    token = parse(make_claims())
    assert token.swname == "CONFIDENTIAL_SPACE"
    assert token.hwmodel == "GCP_AMD_SEV"
    assert token.hardware == "AMD SEV-SNP"
    # Prompt 085: image_digest is read from the NESTED submods path.
    assert token.image_digest == "sha256:" + "ab" * 32
    assert token.instance_id == "3507932791508176595"
    assert token.sub and "instances/enclave-1" in token.sub
    assert token.attester_tcb == ("AMD-SEV-SNP",)
    assert token.dbgstat == "disabled-since-boot"
    assert token.google_service_accounts == ("sa@flare.iam.gserviceaccount.com",)
    assert token.issuer == "https://confidentialcomputing.googleapis.com"
    assert token.audience == DEFAULT_AUDIENCE
    assert token.eat_nonce == "n1"
    assert token.attested is True
    m = token.get_measurements()
    assert m["image_digest"] == "sha256:" + "ab" * 32
    assert m["instance_id"] == "3507932791508176595"
    assert m["sub"] and "instances/enclave-1" in m["sub"]


def test_parse_valid_token_status_response_shape():
    body = parse(make_claims()).to_status_response()
    assert set(body) == {
        "attested", "swname", "image_digest", "hardware", "token_issued_at",
        "instance_id",
    }
    assert body["attested"] is True
    assert body["swname"] == "CONFIDENTIAL_SPACE"
    assert body["hardware"] == "AMD SEV-SNP"
    assert body["instance_id"] == "3507932791508176595"


def test_parse_hwmodel_mapping_intel_tdx():
    token = parse(make_claims(hwmodel="GCP_INTEL_TDX"))
    assert token.hardware == "Intel TDX"


def test_parse_hwmodel_mapping_unknown():
    token = parse(make_claims(hwmodel="GCP_SOME_FUTURE"))
    assert token.hardware == "unknown"


@pytest.mark.parametrize(
    "fixture,exc",
    [
        ("garbage", AttestationTokenError),
        ("two_segments", AttestationTokenError),
        ("bad_b64", AttestationTokenError),
        ("expired", AttestationTokenError),
        ("future_iat", AttestationTokenError),
        ("missing_exp", AttestationTokenError),
        ("wrong_swname", UntrustedEnvironmentError),
        ("missing_swname", UntrustedEnvironmentError),
        ("malformed_digest", AttestationTokenError),
        ("missing_digest", AttestationTokenError),
        ("wrong_audience", AttestationTokenError),
        ("missing_audience", AttestationTokenError),
        ("nonce_mismatch", AttestationTokenError),
        ("missing_nonce", AttestationTokenError),
    ],
)
def test_parse_rejects_invalid_tokens(fixture: str, exc: type[Exception]):
    def factory() -> AttestationToken:
        if fixture == "garbage":
            return AttestationEngine.parse_token("not-a-jwt.at.all")
        if fixture == "two_segments":
            return AttestationEngine.parse_token("abc.def")
        if fixture == "bad_b64":
            return AttestationEngine.parse_token("!!!.!!!.!!!")
        if fixture == "expired":
            return parse(make_claims(exp_offset=-7200.0))
        if fixture == "future_iat":
            return parse(make_claims(iat_offset=+3600.0))
        if fixture == "missing_exp":
            claims = make_claims()
            del claims["exp"]
            return parse(claims)
        if fixture == "wrong_swname":
            return parse(make_claims(swname="NOT_CONFIDENTIAL"))
        if fixture == "missing_swname":
            return parse(make_claims(swname=None))
        if fixture == "malformed_digest":
            return parse(make_claims(image_digest="deadbeef"))
        if fixture == "missing_digest":
            return parse(make_claims(image_digest=None))
        if fixture == "wrong_audience":
            return parse(make_claims(audience="someone-else"))
        if fixture == "missing_audience":
            claims = make_claims()
            del claims["aud"]
            return parse(claims)
        if fixture == "nonce_mismatch":
            return parse(make_claims(nonce="attacker-nonce"))
        if fixture == "missing_nonce":
            return parse(make_claims(nonce=None))
        raise AssertionError(f"unhandled fixture {fixture!r}")

    with pytest.raises(exc):
        factory()


def test_parse_rejects_exp_with_wrong_type():
    claims = make_claims()
    claims["exp"] = "not-a-number"
    with pytest.raises(AttestationTokenError):
        parse(claims)


def test_parse_rejects_fake_top_level_image_digest():
    # Prompt 085: the research-verified path is submods.container.image_digest.
    # A token carrying ONLY the (fake) top-level image_digest must FAIL — we
    # never accept the deceptive shape that the old code used to read.
    claims = make_claims()
    del claims["submods"]  # no submods namespace at all
    claims["image_digest"] = "sha256:" + "ab" * 32  # fake top-level only
    with pytest.raises(AttestationTokenError, match="image_digest"):
        parse(claims)


def test_parse_accepts_nested_image_digest_and_rejects_top_level_alias():
    # Correct shape: nested digest wins, top-level must not even exist.
    claims = make_claims()
    claims["image_digest"] = "sha256:" + "ff" * 32  # decoy top-level
    token = parse(claims)
    assert token.image_digest == "sha256:" + "ab" * 32  # nested is the source of truth


def test_parse_missing_gce_submodule_instance_id_is_none():
    claims = make_claims(instance_id=None)
    token = parse(claims)
    assert token.instance_id is None  # honest absence, never fabricated
    assert token.image_digest.startswith("sha256:")  # container submodule still valid


def test_parse_instance_id_wrong_type_rejected():
    claims = make_claims()
    claims["submods"]["gce"]["instance_id"] = 12345  # not a string
    with pytest.raises(AttestationTokenError, match="instance_id"):
        parse(claims)


def test_engine_nonces_are_fresh_csprng():
    a = AttestationEngine()._nonces[0]
    b = AttestationEngine()._nonces[0]
    assert a != b
    assert len(a) == 32  # 16 random bytes -> 32 hex chars


def test_repr_redacts_raw_token():
    token = parse(make_claims())
    assert token.raw_token not in repr(token)
    # the claims mapping is field(repr=False); serialize it for the check
    assert json.dumps(token.claims) not in repr(token)


def test_errors_derive_from_crypto_error():
    assert issubclass(AttestationError, CryptoError)
    assert issubclass(AttestationServiceUnavailableError, AttestationError)
    assert issubclass(AttestationTokenError, AttestationError)
    assert issubclass(UntrustedEnvironmentError, AttestationError)


# --- REAL local tee server (transport tests) ------------------------------

# responder(body) -> (status, content_type, body_bytes)
Responder = Callable[[bytes], tuple[int, str, bytes]]


def make_server(responder: Responder) -> http.server.HTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:  # silence
            pass

        def do_POST(self) -> None:  # noqa: N802 (http.server naming)
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            status, ctype, payload = responder(body)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    # ThreadingHTTPServer: a slow responder (timeout test) must not stall
    # serve_forever and therefore must not stall shutdown() in the finally.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def echo_responder(body: bytes) -> tuple[int, str, bytes]:
    """The REAL round-trip: echo the request's nonce + audience into claims."""
    req = json.loads(body)
    claims = make_claims(audience=req["audience"], nonce=req["nonces"][0])
    return 200, "application/json", sign_hs256(claims).encode("utf-8")


def engine_url(server: http.server.HTTPServer) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}/v1/token"


def run(coro):
    return asyncio.run(coro)


def test_fetch_vtpm_token_module_level_returns_raw_jwt():
    server = make_server(echo_responder)
    try:
        raw = run(fetch_vtpm_token(endpoint=engine_url(server)))
        assert isinstance(raw, str)
        parts = raw.split(".")
        assert len(parts) == 3  # header.payload.signature
        padded = parts[1] + "=" * (-len(parts[1]) % 4)  # correct JWT padding
        payload = json.loads(base64.urlsafe_b64decode(padded))
        assert payload["swname"] == "CONFIDENTIAL_SPACE"
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_vtpm_token_engine_method_returns_raw_jwt():
    server = make_server(echo_responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        raw = run(engine.fetch_vtpm_token())
        assert isinstance(raw, str)
        assert len(raw.split(".")) == 3
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_token_roundtrip_real_server():
    server = make_server(echo_responder)
    try:
        token = run(AttestationEngine(endpoint=engine_url(server)).fetch_token())
        assert token.swname == "CONFIDENTIAL_SPACE"
        assert token.image_digest.startswith("sha256:")
        assert token.eat_nonce is not None  # nonce echo validated
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_measurements_real_server():
    server = make_server(echo_responder)
    try:
        m = run(AttestationEngine(endpoint=engine_url(server)).fetch_measurements())
        assert m["swname"] == "CONFIDENTIAL_SPACE"
        assert m["attested"] is True
        assert m["hardware"] == "AMD SEV-SNP"
    finally:
        server.shutdown()
        server.server_close()


def test_wrapped_json_token_response_accepted():
    def responder(_body: bytes) -> tuple[int, str, bytes]:
        payload = json.dumps({"token": sign_hs256(make_claims(nonce="w1"))}).encode()
        return 200, "application/json", payload

    server = make_server(responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server), nonces=["w1"])
        token = run(engine.fetch_token())
        assert token.swname == "CONFIDENTIAL_SPACE"
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_endpoint_fails_closed():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()  # nothing listening -> connection refused
    engine = AttestationEngine(endpoint=f"http://127.0.0.1:{dead_port}/v1/token")
    with pytest.raises(AttestationServiceUnavailableError):
        run(engine.fetch_token())


def test_empty_body_fails_closed():
    server = make_server(lambda _b: (200, "application/json", b""))
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        with pytest.raises(AttestationServiceUnavailableError, match="empty body"):
            run(engine.fetch_token())
    finally:
        server.shutdown()
        server.server_close()


def test_timeout_fails_closed():
    def slow(_body: bytes) -> tuple[int, str, bytes]:
        time.sleep(2.0)
        return 200, "application/json", b"late"

    server = make_server(slow)
    try:
        engine = AttestationEngine(endpoint=engine_url(server), timeout=0.3)
        with pytest.raises(AttestationServiceUnavailableError):
            run(engine.fetch_token())
    finally:
        server.shutdown()
        server.server_close()


def test_non_utf8_body_fails_closed():
    """Prompt 095 — a hostile/broken tee server answering with non-UTF-8
    garbage must map to the TYPED fail-closed error, never leak a raw
    UnicodeDecodeError to the caller (probe: b"\\xff\\xfe" escaped as
    UnicodeDecodeError before the fix)."""
    server = make_server(lambda _b: (200, "application/json", b"\xff\xfe\x00bad"))
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        with pytest.raises(AttestationServiceUnavailableError, match="UnicodeDecodeError"):
            run(engine.fetch_token())
    finally:
        server.shutdown()
        server.server_close()


def test_http_error_status_fails_closed():
    """Prompt 095 — an HTTP 500 from the tee server (HTTPError, a URLError
    subclass) maps to the TYPED fail-closed error, never leaks."""
    server = make_server(lambda _b: (500, "text/plain", b"boom"))
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        with pytest.raises(AttestationServiceUnavailableError, match="HTTPError"):
            run(engine.fetch_token())
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_endpoint_fails_closed_module_function():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    with pytest.raises(AttestationServiceUnavailableError):
        run(fetch_vtpm_token(endpoint=f"http://127.0.0.1:{dead_port}/v1/token"))


# --- Opener selection logic -----------------------------------------------


def test_opener_http_when_socket_path_absent():
    engine = AttestationEngine(socket_path="/nonexistent/teeserver.sock")
    handlers = engine._build_opener().handlers
    assert not any(
        type(h).__name__ == "_UnixSocketHTTPHandler" for h in handlers
    )


def test_opener_never_uses_socket_without_af_unix():
    if hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX available: socket branch is the live contract")
    # Even a present-looking path must NOT select the socket handler when
    # the Python build lacks AF_UNIX (reviewer hardening, Prompt 081).
    engine = AttestationEngine(socket_path=TEESERVER_SOCKET)
    handlers = engine._build_opener().handlers
    assert not any(
        type(h).__name__ == "_UnixSocketHTTPHandler" for h in handlers
    )


def test_default_timeout_and_endpoint_constants():
    assert AttestationEngine()._endpoint == "http://localhost/v1/token"
    assert DEFAULT_TIMEOUT_S > 0
    assert TEESERVER_SOCKET == "/run/container_launcher/teeserver.sock"


# ---------------------------------------------------------------------------
# Prompt 083 — Intel Trust Authority (ITA) fallback
# ---------------------------------------------------------------------------


def make_intel_claims(
    *,
    audience: str = DEFAULT_AUDIENCE,
    nonce: str | None = "n1",
    swname: str = "CONFIDENTIAL_SPACE",
    hwmodel: str = EXPECTED_TDX_HWMODEL,
    issuer: str = ITA_OIDC_ISSUER,
    exp_offset: float = 3600.0,
    iat_offset: float = -5.0,
    **extra: Any,
) -> dict[str, Any]:
    """A realistic ITA token claim set (research-verified claim names)."""
    now = time.time()
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": "projects/flare-prod/zones/us-central1-a/instances/enclave-1",
        "aud": audience,
        "iat": int(now + iat_offset),
        "exp": int(now + exp_offset),
        "swname": swname,
        "hwmodel": hwmodel,
        "attester_tcb": ["INTEL"],
        "tdx": {
            "tdx_mrtd": "ab" * 48,
            "tdx_rtmr0": "cd" * 48,
            "tdx_rtmr1": "ef" * 48,
            "tdx_rtmr2": "01" * 48,
            "tdx_mrseam": "23" * 48,
        },
        "policy_ids_matched": [{"id": "policy-abc-123"}],
        "policy_ids_unmatched": [],
        "container": {
            "image_reference": "ghcr.io/flare-verifiable-rag/enclave:dev",
            "image_digest": "sha256:" + "0123456789abcdef" * 4,
        },
    }
    if nonce is not None:
        claims["eat_nonce"] = nonce
    claims.update(extra)
    return claims


def parse_intel(claims: dict[str, Any], **kw: Any) -> IntelAttestationToken:
    return AttestationEngine.parse_intel_token(
        sign_hs256(claims),
        expected_audience=kw.pop("expected_audience", DEFAULT_AUDIENCE),
        expected_nonces=kw.pop("expected_nonces", ("n1",)),
        **kw,
    )


# --- ITA parse/validation --------------------------------------------------


def test_parse_intel_token_valid_measurements():
    token = parse_intel(make_intel_claims())
    assert token.issuer == ITA_OIDC_ISSUER
    assert token.swname == "CONFIDENTIAL_SPACE"
    assert token.hwmodel == EXPECTED_TDX_HWMODEL
    assert token.attester_tcb == ("INTEL",)
    assert token.sub and "instances/enclave-1" in token.sub
    assert token.tdx_quote is not None
    assert token.policy_ids_matched == ("policy-abc-123",)
    assert token.policy_ids_unmatched == ()
    assert token.container["image_digest"].startswith("sha256:")
    assert token.attested is True
    m = token.get_measurements()
    assert m["attester_tcb"] == ["INTEL"]
    assert m["tdx_quote"]["tdx_mrtd"]


def test_parse_intel_token_rejects_wrong_issuer():
    with pytest.raises(AttestationTokenError, match="issuer"):
        parse_intel(make_intel_claims(issuer="https://evil.example.com"))


def test_parse_intel_token_rejects_non_tdx_hardware():
    with pytest.raises(AttestationTokenError, match="hwmodel"):
        parse_intel(make_intel_claims(hwmodel="GCP_AMD_SEV"))


def test_parse_intel_token_rejects_wrong_tcb():
    claims = make_intel_claims()
    claims["attester_tcb"] = ["AMD-SEV-SNP"]  # not the Intel root of trust
    with pytest.raises(AttestationTokenError, match="attester_tcb"):
        parse_intel(claims)


def test_parse_intel_token_rejects_untrusted_swname():
    # Research: swname == "GCE" when TDX passes but RIM verification fails.
    with pytest.raises(UntrustedEnvironmentError):
        parse_intel(make_intel_claims(swname="GCE"))


def test_parse_intel_token_rejects_expired():
    with pytest.raises(AttestationTokenError):
        parse_intel(make_intel_claims(exp_offset=-7200.0))


def test_parse_intel_token_rejects_future_iat():
    with pytest.raises(AttestationTokenError):
        parse_intel(make_intel_claims(iat_offset=+3600.0))


def test_parse_intel_token_rejects_audience_mismatch():
    with pytest.raises(AttestationTokenError, match="audience"):
        parse_intel(make_intel_claims(audience="someone-else"))


def test_parse_intel_token_rejects_nonce_mismatch():
    with pytest.raises(AttestationTokenError, match="nonce"):
        parse_intel(make_intel_claims(nonce="attacker-nonce"))


def test_parse_intel_token_rejects_missing_nonce():
    with pytest.raises(AttestationTokenError, match="nonce"):
        parse_intel(make_intel_claims(nonce=None))


def test_parse_intel_token_rejects_garbage():
    with pytest.raises(AttestationTokenError):
        AttestationEngine.parse_intel_token("not.a.jwt")
    with pytest.raises(AttestationTokenError):
        AttestationEngine.parse_intel_token("abc.def")


def test_parse_intel_token_accepts_nonce_alias_claim():
    # Some launcher versions echo the nonce as `nonce` instead of eat_nonce.
    claims = make_intel_claims()
    del claims["eat_nonce"]
    claims["nonce"] = "n1"
    token = parse_intel(claims)
    assert token.eat_nonce == "n1"


def test_is_tdx_hardware_detection():
    tdx = parse(make_claims(hwmodel="GCP_INTEL_TDX"))
    amd = parse(make_claims(hwmodel="GCP_AMD_SEV"))
    assert is_tdx_hardware(tdx) is True
    assert is_tdx_hardware(amd) is False


def test_intel_token_repr_redacts_raw():
    token = parse_intel(make_intel_claims())
    assert token.raw_token not in repr(token)
    assert json.dumps(token.claims) not in repr(token)


# --- ITA transport (real local server) -------------------------------------


def intel_echo_responder(body: bytes) -> tuple[int, str, bytes]:
    req = json.loads(body)
    claims = make_intel_claims(audience=req["audience"], nonce=req["nonces"][0])
    return 200, "application/json", sign_hs256(claims).encode("utf-8")


def test_fetch_intel_token_engine_method_real_server():
    server = make_server(intel_echo_responder)
    try:
        engine = AttestationEngine(intel_endpoint=engine_url(server))
        raw = run(engine.fetch_intel_token())
        assert isinstance(raw, str)
        assert len(raw.split(".")) == 3
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_intel_token_module_level_real_server():
    server = make_server(intel_echo_responder)
    try:
        raw = run(fetch_intel_token(endpoint=engine_url(server)))
        assert len(raw.split(".")) == 3
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_intel_attestation_roundtrip_real_server():
    server = make_server(intel_echo_responder)
    try:
        token = run(
            AttestationEngine(intel_endpoint=engine_url(server)).fetch_intel_attestation()
        )
        assert token.issuer == ITA_OIDC_ISSUER
        assert token.hwmodel == EXPECTED_TDX_HWMODEL
        assert token.eat_nonce is not None
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_intel_token_unreachable_fails_closed():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    engine = AttestationEngine(intel_endpoint=f"http://127.0.0.1:{dead_port}/v1/intel/token")
    with pytest.raises(AttestationServiceUnavailableError):
        run(engine.fetch_intel_token())


# --- Fallback orchestration (fetch_token_with_fallback) --------------------


def _tdx_primary_responder(body: bytes) -> tuple[int, str, bytes]:
    req = json.loads(body)
    claims = make_claims(
        audience=req["audience"], nonce=req["nonces"][0], hwmodel="GCP_INTEL_TDX"
    )
    return 200, "application/json", sign_hs256(claims).encode("utf-8")


def _amd_primary_responder(body: bytes) -> tuple[int, str, bytes]:
    req = json.loads(body)
    claims = make_claims(
        audience=req["audience"], nonce=req["nonces"][0], hwmodel="GCP_AMD_SEV"
    )
    return 200, "application/json", sign_hs256(claims).encode("utf-8")


def test_fallback_amd_skips_intel_fetch():
    primary = make_server(_amd_primary_responder)
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        engine = AttestationEngine(
            endpoint=engine_url(primary),
            intel_endpoint=f"http://127.0.0.1:{dead_port}/v1/intel/token",
        )
        result = run(engine.fetch_token_with_fallback())
        assert isinstance(result, AttestationWithIntel)
        assert result.primary.hwmodel == "GCP_AMD_SEV"
        assert result.intel is None  # no ITA fallback on AMD
    finally:
        primary.shutdown()
        primary.server_close()


def test_fallback_tdx_fetches_and_validates_intel():
    primary = make_server(_tdx_primary_responder)
    intel = make_server(intel_echo_responder)
    try:
        engine = AttestationEngine(
            endpoint=engine_url(primary), intel_endpoint=engine_url(intel)
        )
        result = run(engine.fetch_token_with_fallback())
        assert result.primary.hwmodel == EXPECTED_TDX_HWMODEL
        assert is_tdx_hardware(result.primary)
        assert result.intel is not None
        assert result.intel.issuer == ITA_OIDC_ISSUER
        assert result.intel.hwmodel == EXPECTED_TDX_HWMODEL
        assert result.intel.eat_nonce is not None
    finally:
        primary.shutdown()
        primary.server_close()
        intel.shutdown()
        intel.server_close()


def test_fallback_tdx_intel_unavailable_fails_closed():
    primary = make_server(_tdx_primary_responder)
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        engine = AttestationEngine(
            endpoint=engine_url(primary),
            intel_endpoint=f"http://127.0.0.1:{dead_port}/v1/intel/token",
        )
        # TDX detected -> ITA fallback is MANDATORY -> fail closed.
        with pytest.raises(AttestationServiceUnavailableError):
            run(engine.fetch_token_with_fallback())
    finally:
        primary.shutdown()
        primary.server_close()


def test_intel_endpoint_constant():
    assert INTEL_TOKEN_ENDPOINT == "http://localhost/v1/intel/token"
    assert AttestationEngine()._intel_endpoint == INTEL_TOKEN_ENDPOINT


# ---------------------------------------------------------------------------
# Prompt 087 — generate_attestation_proof (token + digest + ZKP binding)
# ---------------------------------------------------------------------------


def test_generate_attestation_proof_combines_all_three(fake_engine):
    """Real tee server (real signed token) + REAL engine call shape → the
    three components land in one record with a recomputable binding hash."""
    server = make_server(echo_responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        proof = run(engine.generate_attestation_proof("clause 4 governs", "what governs?"))
        assert isinstance(proof, AttestationProof)
        assert proof.swname == "CONFIDENTIAL_SPACE"
        assert proof.image_digest.startswith("sha256:")
        assert proof.hardware == "AMD SEV-SNP"
        assert proof.zk_proof  # real engine output (fake wheel shape)
        assert all(len(p) == 32 for p in proof.public_inputs)
        assert len(proof.raw_token.split(".")) == 3  # header.payload.signature
    finally:
        server.shutdown()
        server.server_close()


def test_attestation_proof_binding_hash_recomputable(fake_engine):
    server = make_server(echo_responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        proof = run(engine.generate_attestation_proof("doc", "prompt"))
        recomputed = AttestationProof.compute_binding_hash(
            proof.image_digest, proof.zk_proof, proof.public_inputs
        )
        assert proof.binding_hash == recomputed
        assert len(proof.binding_hash) == 64  # sha256 hex
        # Tampering with ANY component changes the binding (swapped-proof detect).
        alt = AttestationProof.compute_binding_hash(
            proof.image_digest, b"\x00" + proof.zk_proof[1:], proof.public_inputs
        )
        assert alt != proof.binding_hash
        alt2 = AttestationProof.compute_binding_hash(
            "sha256:" + "ff" * 32, proof.zk_proof, proof.public_inputs
        )
        assert alt2 != proof.binding_hash
    finally:
        server.shutdown()
        server.server_close()


def test_attestation_proof_public_inputs_are_engine_outputs(fake_engine):
    server = make_server(echo_responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        proof = run(engine.generate_attestation_proof("doc", "prompt"))
        import hashlib

        expected_doc = hashlib.sha256(b"doc").digest()
        expected_prompt = hashlib.sha256(b"prompt").digest()
        expected_out = hashlib.sha256(expected_doc + expected_prompt).digest()
        assert proof.public_inputs == (expected_doc, expected_prompt, expected_out)
    finally:
        server.shutdown()
        server.server_close()


def test_generate_attestation_proof_fails_closed_on_tee_down(fake_engine):
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()
    engine = AttestationEngine(endpoint=f"http://127.0.0.1:{dead_port}/v1/token")
    with pytest.raises(AttestationServiceUnavailableError):
        run(engine.generate_attestation_proof("doc", "prompt"))


def test_generate_attestation_proof_fails_closed_on_missing_wheel():
    server = make_server(echo_responder)
    try:
        engine = AttestationEngine(endpoint=engine_url(server))
        prev = sys.modules.get("indexer_rs")
        sys.modules["indexer_rs"] = None  # import indexer_rs -> ImportError
        try:
            with pytest.raises(RuntimeError, match="not installed"):
                run(engine.generate_attestation_proof("doc", "prompt"))
        finally:
            if prev is not None:
                sys.modules["indexer_rs"] = prev
            else:
                sys.modules.pop("indexer_rs", None)
    finally:
        server.shutdown()
        server.server_close()


def test_generate_attestation_proof_module_level(fake_engine):
    server = make_server(echo_responder)
    try:
        proof = run(generate_attestation_proof("doc", "prompt", endpoint=engine_url(server)))
        assert isinstance(proof, AttestationProof)
        assert proof.attested is True
    finally:
        server.shutdown()
        server.server_close()


def test_attestation_proof_record_shape(fake_engine):
    server = make_server(echo_responder)
    try:
        proof = run(generate_attestation_proof("doc", "prompt", endpoint=engine_url(server)))
        rec = proof.to_record()
        assert set(rec) == {
            "attested", "swname", "image_digest", "hardware",
            "zk_proof", "public_inputs", "binding_hash",
        }
        assert len(rec["public_inputs"]) == 3
        assert all(len(h) == 64 for h in rec["public_inputs"])
        import base64 as _b64

        assert _b64.b64decode(rec["zk_proof"]) == proof.zk_proof
    finally:
        server.shutdown()
        server.server_close()


def test_attestation_proof_repr_redacts_raw_token(fake_engine):
    server = make_server(echo_responder)
    try:
        proof = run(generate_attestation_proof("doc", "prompt", endpoint=engine_url(server)))
        assert proof.raw_token not in repr(proof)
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# Prompt 090 — OIDC claim parsing against the standard Confidential Space
# token schema (user-pro-verified research: cloud.google.com/confidential-
# computing/confidential-space/docs/reference/token-claims)
# ---------------------------------------------------------------------------
#
# The standard GCP Confidential Space OIDC token carries:
#   * top-level: iss, aud, sub (the VM self-link URI), iat, exp, nbf, jti,
#     eat_nonce (string OR array of strings), swname (CONFIDENTIAL_SPACE /
#     GCE), swversion (array), hwmodel (GCP_AMD_SEV / GCP_AMD_SEV_ES /
#     GCP_SHIELDED_VM / GCP_INTEL_TDX), dbgstat (disabled-since-boot /
#     enabled), attester_tcb, google_service_accounts, secboot (bool),
#     oemid (uint64; 11129 = Google PEN);
#   * submods.container.{image_digest, image_id, restart_policy,
#     cmd_override, args, env, env_override};
#   * submods.gce.{instance_id, project_id, project_number, zone}.
#
# The research confirms: instance_id is NESTED ONLY (never top-level), and
# the standard token does NOT emit raw vtpm PCRs — the attestation backend
# abstracts the PCR measurements into semantic claims (swname,
# image_digest). Every fixture here is genuinely HS256-signed.


def _standard_schema_claims(**overrides: Any) -> dict[str, Any]:
    """The FULL standard GCP Confidential Space claim set — every
    documented top-level + submods claim, exactly per the token-claims
    reference (research, Prompt 090).

    NOTE: deliberately a STANDALONE builder (not a make_claims call) — it
    diverges from the minimal fixture in ~8 fields; if the nested claim
    shape ever changes (as it did in Prompt 085), keep both in sync."""
    now = time.time()
    claims: dict[str, Any] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": DEFAULT_AUDIENCE,
        # The research: sub is the fully-qualified VM self-link URI.
        "sub": "https://www.googleapis.com/compute/v1/projects/flare-prod/"
        "zones/us-central1-a/instances/enclave-1",
        "iat": int(now - 5),
        "exp": int(now + 3600),
        "nbf": int(now - 5),
        "jti": secrets.token_hex(16),
        "eat_nonce": ["n1"],  # EAT: string OR array of strings
        "swname": EXPECTED_SWNAME,
        "swversion": ["240500", "240501"],
        "hwmodel": "GCP_INTEL_TDX",
        "dbgstat": "disabled-since-boot",
        "attester_tcb": ["INTEL"],
        "google_service_accounts": [
            "rag-sa@flare.iam.gserviceaccount.com",
            "ops-sa@flare.iam.gserviceaccount.com",
        ],
        "secboot": True,
        "oemid": 11129,  # Google Private Enterprise Number (PEN)
        "submods": {
            "container": {
                "image_digest": "sha256:" + "ab" * 32,
                "image_id": "sha256:" + "cd" * 32,
                "restart_policy": "Always",
                "cmd_override": ["sleep", "infinity"],
                "args": ["/usr/bin/rag-enclave"],
                "env": {"RAG_MODE": "production"},
                "env_override": {"LOG_LEVEL": "info"},
            },
            "gce": {
                "instance_id": "3507932791508176595",
                "project_id": "flare-prod",
                "project_number": "123456789012",
                "zone": "us-central1-a",
            },
        },
    }
    claims.update(overrides)
    return claims


def test_parse_full_standard_confidential_space_schema():
    """A token carrying EVERY standard claim parses with each field landed
    on the model — nothing dropped, nothing fabricated."""
    token = parse(_standard_schema_claims())
    assert token.attested is True
    assert token.swname == EXPECTED_SWNAME
    assert token.hardware == "Intel TDX"
    assert token.issuer == "https://confidentialcomputing.googleapis.com"
    assert token.audience == DEFAULT_AUDIENCE
    assert token.sub == (
        "https://www.googleapis.com/compute/v1/projects/flare-prod/"
        "zones/us-central1-a/instances/enclave-1"
    )
    assert token.image_digest == "sha256:" + "ab" * 32
    assert token.instance_id == "3507932791508176595"
    assert token.swversion == ("240500", "240501")
    assert token.dbgstat == "disabled-since-boot"
    assert token.attester_tcb == ("INTEL",)
    assert token.google_service_accounts == (
        "rag-sa@flare.iam.gserviceaccount.com",
        "ops-sa@flare.iam.gserviceaccount.com",
    )
    assert token.eat_nonce == ["n1"]  # raw claim preserved (array form)
    # Standard claims preserved verbatim on the claims mapping.
    assert token.claims["jti"]
    assert token.claims["secboot"] is True
    assert token.claims["oemid"] == 11129
    assert token.claims["nbf"] == token.claims["iat"]
    container = token.claims["submods"]["container"]
    assert container["cmd_override"] == ["sleep", "infinity"]
    assert container["env"] == {"RAG_MODE": "production"}
    gce = token.claims["submods"]["gce"]
    assert gce["project_number"] == "123456789012"
    assert gce["zone"] == "us-central1-a"


def test_parse_standard_schema_with_and_without_vtpm_submodule():
    """Per the research, the STANDARD token does not carry raw vtpm PCRs —
    the attestation backend distills the measurements into semantic claims
    (swname, image_digest), so a standard token parses with no
    ``submods.vtpm`` and no error. A token that DOES carry raw PCRs (a
    custom hybrid TEE pipeline, also per the research) is tolerated — the
    parser never rejects unknown submods."""
    standard = parse(_standard_schema_claims())
    assert standard.attested is True
    assert "vtpm" not in standard.claims.get("submods", {})
    assert standard.image_digest.startswith("sha256:")  # the distilled claim

    extended = _standard_schema_claims()
    extended["submods"]["vtpm"] = {
        "pcr0": "ab" * 32,
        "pcr1": "cd" * 32,
        "pcr2": "ef" * 32,
        "pcr8": "01" * 32,
    }
    token = parse(extended)
    assert token.attested is True
    assert token.claims["submods"]["vtpm"]["pcr0"] == "ab" * 32


@pytest.mark.parametrize(
    "hwmodel,expected_family",
    [
        ("GCP_AMD_SEV", "AMD SEV-SNP"),
        ("GCP_INTEL_TDX", "Intel TDX"),
        # Documented standard values not yet in the family map — honestly
        # reported as "unknown", never mislabeled as an attested family.
        ("GCP_AMD_SEV_ES", "unknown"),
        ("GCP_SHIELDED_VM", "unknown"),
        ("GCP_INTEL_SAPPHIRE_RAPIDS", "unknown"),
    ],
)
def test_parse_hwmodel_standard_values(hwmodel: str, expected_family: str):
    token = parse(make_claims(hwmodel=hwmodel))
    assert token.hardware == expected_family


def test_parse_hwmodel_absent_reports_unknown():
    claims = make_claims()
    del claims["hwmodel"]
    token = parse(claims)
    assert token.hardware == "unknown"


@pytest.mark.parametrize("dbgstat", ["disabled-since-boot", "enabled", "disabled-user-set"])
def test_parse_dbgstat_standard_values(dbgstat: str):
    token = parse(make_claims(dbgstat=dbgstat))
    assert token.dbgstat == dbgstat


def test_parse_eat_nonce_array_form_accepted():
    """EAT nonce is a string OR array of strings; an array containing the
    expected nonce satisfies the anti-replay echo check (the model preserves
    the raw claim value — the array is not flattened)."""
    claims = make_claims()
    claims["eat_nonce"] = ["n1", "second-nonce"]
    token = parse(claims)  # would raise on a failed echo check
    assert token.attested is True
    assert token.eat_nonce == ["n1", "second-nonce"]


def test_parse_multi_audience_with_matching_azp_accepted():
    """OIDC Core: multiple audiences REQUIRE azp == the relying party's
    audience (confused-deputy defense)."""
    token = parse(
        make_claims(aud=[DEFAULT_AUDIENCE, "second-audience"], azp=DEFAULT_AUDIENCE)
    )
    assert token.audience == [DEFAULT_AUDIENCE, "second-audience"]


def test_parse_multi_audience_without_azp_rejected():
    with pytest.raises(AttestationTokenError, match="azp"):
        parse(make_claims(aud=[DEFAULT_AUDIENCE, "second-audience"]))


def test_parse_multi_audience_with_mismatched_azp_rejected():
    with pytest.raises(AttestationTokenError, match="azp"):
        parse(
            make_claims(
                aud=[DEFAULT_AUDIENCE, "second-audience"], azp="someone-else"
            )
        )


def test_parse_single_audience_with_mismatched_azp_rejected():
    with pytest.raises(AttestationTokenError, match="azp"):
        parse(make_claims(azp="someone-else"))


def test_parse_nbf_schema_past_accepted_future_rejected():
    now = int(time.time())
    past = parse(make_claims(nbf=now - 100))
    assert past.attested is True
    with pytest.raises(AttestationTokenError, match="not yet valid"):
        parse(make_claims(nbf=now + 3600))


def test_parse_sub_is_optional_for_primary_tokens():
    """The parser contract (jwt_parser): primary Confidential Space tokens
    may omit sub (require_sub is enforced for ITA tokens, not here)."""
    claims = make_claims()
    del claims["sub"]
    token = parse(claims)
    assert token.attested is True
    assert token.sub is None


def test_parse_rejects_swname_gce_standard_value():
    """The research: swname == "GCE" is the REAL value when the image FAILS
    validation (not an attested Confidential Space) — fail closed."""
    with pytest.raises(UntrustedEnvironmentError):
        parse(make_claims(swname="GCE"))


# ---------------------------------------------------------------------------
# Prompt 092 — attestation.py <-> connector.py connection (tokens ride in
# Flare transactions)
# ---------------------------------------------------------------------------
#
# User-pro-verified research (Prompt 092): production TEE systems (Phala,
# Flashbots, Oasis, Chainlink Functions) attach attestation evidence to
# transactions as calldata — but ONLY the cheap commitment, never the raw
# 1.5-3 KB JWT (24-48K gas calldata + prohibitive on-chain verification).
# The canonical VerifiableRAG interface is a SINGLE ABI struct
# (bytes32 bindingHash, bytes zkProof, bytes32[3] publicInputs), and a
# one-time registerEnclave path (Pattern A) for the raw token (emitted via
# event, never stored). These tests pin the payload shapers + the glue to
# the connector, using a genuinely HS256-signed token and REAL SHA-256
# derived proof bytes — no fabricated business data.


def _real_proof() -> AttestationProof:
    """A REAL AttestationProof: genuinely signed token + real SHA-256-derived
    proof bytes + the recomputable binding hash (nothing fabricated). The
    zk_proof bytes are deterministic stand-ins (the compiled wheel is
    exercised elsewhere); the binding hash is computed over them exactly as
    production does."""
    token = parse(make_claims())  # genuinely HS256-signed, validated
    doc_h = hashlib.sha256(b"clause 4 governs").digest()
    prompt_h = hashlib.sha256(b"what governs?").digest()
    out_h = hashlib.sha256(doc_h + prompt_h).digest()
    public_inputs = (doc_h, prompt_h, out_h)
    zk_proof = b"zk-proof-bytes-" + doc_h[:8]
    return AttestationProof(
        raw_token=token.raw_token,
        image_digest=token.image_digest,
        swname=token.swname,
        hardware=token.hardware,
        zk_proof=zk_proof,
        public_inputs=public_inputs,
        binding_hash=AttestationProof.compute_binding_hash(
            token.image_digest, zk_proof, public_inputs
        ),
    )


def test_proof_to_flare_payload_shape():
    """The single-ABI-struct payload: bindingHash as 0x-bytes32 hex, zkProof
    as raw bytes, publicInputs as three 0x bytes32 hex — plus the record as
    the payload bytes (contract log/index). The raw JWT is NOT included
    (research: commitment-only on-chain)."""
    proof = _real_proof()
    payload = proof.to_flare_payload()
    assert set(payload) == {"proof", "payload"}
    struct = payload["proof"]
    assert set(struct) == {"bindingHash", "zkProof", "publicInputs"}
    assert struct["bindingHash"] == "0x" + proof.binding_hash
    assert len(struct["bindingHash"]) == 66  # 0x + 64 hex (bytes32)
    assert struct["zkProof"] == proof.zk_proof  # raw bytes, web3-encodable
    assert len(struct["publicInputs"]) == 3
    assert all(len(h) == 66 and h.startswith("0x") for h in struct["publicInputs"])
    assert struct["publicInputs"] == ["0x" + p.hex() for p in proof.public_inputs]
    # payload = the JSON-serialized execution record, byte-for-byte.
    assert json.loads(payload["payload"]) == proof.to_record()
    # The raw token deliberately stays OFF the transaction payload.
    assert proof.raw_token not in repr(payload)


def test_proof_to_flare_payload_rejects_malformed_public_inputs():
    proof = _real_proof()
    bad = AttestationProof(
        raw_token=proof.raw_token,
        image_digest=proof.image_digest,
        swname=proof.swname,
        hardware=proof.hardware,
        zk_proof=proof.zk_proof,
        public_inputs=(b"x", b"y", b"z"),  # not 32-byte field reprs
        binding_hash=proof.binding_hash,
    )
    with pytest.raises(ValueError, match="32-byte"):
        bad.to_flare_payload()


def test_proof_to_flare_payload_values_abi_encodable():
    """Real proof: the shaped values encode through eth_abi exactly as the
    Solidity struct tuple ``(bytes32, bytes, bytes32[3])`` — proving the
    payload is valid calldata, not just a pretty dict."""
    from eth_abi import encode

    proof = _real_proof()
    payload = proof.to_flare_payload()
    struct = payload["proof"]
    encoded = encode(
        ["bytes32", "bytes", "bytes32[3]"],
        [
            bytes.fromhex(struct["bindingHash"][2:]),
            struct["zkProof"],
            [bytes.fromhex(h[2:]) for h in struct["publicInputs"]],
        ],
    )
    assert isinstance(encoded, bytes) and len(encoded) > 0
    # Determinism: the same payload always encodes to the same calldata.
    assert encode(
        ["bytes32", "bytes", "bytes32[3]"],
        [
            bytes.fromhex(struct["bindingHash"][2:]),
            struct["zkProof"],
            [bytes.fromhex(h[2:]) for h in struct["publicInputs"]],
        ],
    ) == encoded


def test_token_to_registration_payload_shape():
    """Pattern A (one-time registerEnclave): the raw JWT + identity claims as
    calldata strings — the contract emits the token, never stores it."""
    token = parse(make_claims())
    payload = token.to_registration_payload()
    assert set(payload) == {"jwtToken", "imageDigest", "swname", "instanceId"}
    assert payload["jwtToken"] == token.raw_token
    assert len(payload["jwtToken"].split(".")) == 3  # a real JWT
    assert payload["imageDigest"] == token.image_digest
    assert payload["swname"] == "CONFIDENTIAL_SPACE"
    assert payload["instanceId"] == "3507932791508176595"


def test_token_registration_payload_instance_id_empty_when_absent():
    token = parse(make_claims(instance_id=None))
    payload = token.to_registration_payload()
    assert payload["instanceId"] == ""  # honest empty, never fabricated


class _RecordingClient:
    """Minimal async test double of the connector's submission interface
    (offline unit test — the REAL client needs a live chain + the Phase 6
    contract). Records the exact payload/args it receives and returns a
    receipt whose tx hash is REALLY derived (sha256 of the payload), so the
    glue's passthrough is asserted honestly."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit_attestation(
        self,
        payload: dict[str, Any],
        *,
        fn_name: str | None = None,
        value_wei: int = 0,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "payload": payload,
                "fn_name": fn_name,
                "value_wei": value_wei,
                "private_key": private_key,
            }
        )
        digest = hashlib.sha256(repr(payload).encode("utf-8")).hexdigest()
        return {"tx_hash": "0x" + digest, "status": 1}


def test_submit_attestation_to_flare_proof_path():
    """The glue passes the EXACT proof payload (struct shape) through to the
    client's submission pipeline and forwards the caller's options."""
    proof = _real_proof()
    client = _RecordingClient()
    receipt = run(
        submit_attestation_to_flare(
            client, proof, fn_name="submitAttestation", value_wei=1
        )
    )
    assert client.calls == [
        {
            "payload": proof.to_flare_payload(),
            "fn_name": "submitAttestation",
            "value_wei": 1,
            "private_key": None,
        }
    ]
    assert receipt["status"] == 1
    assert receipt["tx_hash"].startswith("0x")


def test_submit_attestation_to_flare_token_path():
    """The glue routes an AttestationToken to the registration payload
    (Pattern A) with the explicit function name."""
    token = parse(make_claims())
    client = _RecordingClient()
    run(
        submit_attestation_to_flare(
            client, token, fn_name="registerEnclave", value_wei=0
        )
    )
    assert client.calls[0]["payload"] == token.to_registration_payload()
    assert client.calls[0]["fn_name"] == "registerEnclave"


def test_submit_attestation_to_flare_rejects_unknown_record():
    with pytest.raises(TypeError, match="AttestationProof or AttestationToken"):
        run(submit_attestation_to_flare(_RecordingClient(), "not-a-record"))

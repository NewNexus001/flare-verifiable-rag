"""Prompt 089 — permanent tests for the local vTPM test double.

Proves :mod:`mock_vtpm` (enclave/tests/mock_vtpm.py) against the REAL
enclave fetch path — ``AttestationEngine`` (src.crypto.attestation)
configured to talk to a running :class:`MockVtpmDaemon`. Nothing is
monkeypatched on the transport: the engine issues its real POST, the daemon
answers with genuinely signed tokens, and the enclave's real parsing,
validation, and fail-closed logic runs unmodified.

Covered:

* **AMD + TDX modes** — primary-only on AMD; primary + Intel Trust
  Authority (``/v1/intel/token``) on TDX, exactly the mandatory-fallback
  shape the engine expects.
* **Genuinely signed tokens** — HS256 under a per-daemon CSPRNG key
  (default) AND RS256 with an ephemeral RSA-2048 keypair whose signature is
  cryptographically VERIFIED against the daemon's public key.
* **Real claim shapes (Prompt 085)** — image_digest NESTED at
  ``submods.container.image_digest``, instance_id at ``submods.gce``, nonce
  echo (``eat_nonce``).
* **Stateful fault injection** — down (503), empty body, garbage bytes, and
  slow (timeout) all drive the engine to its typed fail-closed errors.
* **Unix-socket transport** — mirrors the launcher's real socket so the
  engine's ``_UnixSocketHTTPConnection`` path is exercised (skipped when the
  platform lacks AF_UNIX).

The ``assert_no_disk_io`` autouse fixture (conftest) applies: socket
binding/cleanup never touches the file API.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import tempfile

import pytest
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from mock_vtpm import (
    EXPECTED_SWNAME,
    HWMODEL_AMD,
    HWMODEL_TDX,
    ITA_OIDC_ISSUER,
    MockVtpmDaemon,
    OIDC_ISSUER,
)
from src.crypto.attestation import (
    AttestationEngine,
    AttestationServiceUnavailableError,
    AttestationTokenError,
    DEFAULT_AUDIENCE,
)


def run(coro):
    return asyncio.run(coro)


def decode_payload(jwt_token: str) -> dict:
    seg = jwt_token.split(".")[1]
    padded = seg + "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# --- AMD / TDX contract ----------------------------------------------------


def test_amd_daemon_primary_real_jwt_roundtrip():
    with MockVtpmDaemon(hwmodel=HWMODEL_AMD) as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url)
        token = run(engine.fetch_token())
        assert token.swname == EXPECTED_SWNAME
        assert token.hardware == "AMD SEV-SNP"
        assert token.issuer == OIDC_ISSUER
        # Prompt 085: the NESTED claim paths, not a fake top-level shape.
        assert token.image_digest == "sha256:" + "cd" * 32
        assert token.instance_id == "3507932791508176595"
        assert token.audience == DEFAULT_AUDIENCE
        # The daemon echoes the engine's nonce — anti-replay check passes.
        assert token.eat_nonce == engine._nonces[0]


def test_tdx_daemon_serves_intel_endpoint_mandatory_fallback():
    with MockVtpmDaemon(hwmodel=HWMODEL_TDX) as daemon:
        engine = AttestationEngine(
            endpoint=daemon.primary_url, intel_endpoint=daemon.intel_url
        )
        result = run(engine.fetch_token_with_fallback())
        assert result.primary.hwmodel == HWMODEL_TDX
        assert result.intel is not None
        assert result.intel.issuer == ITA_OIDC_ISSUER
        assert result.intel.attester_tcb == ("INTEL",)
        assert result.intel.tdx_quote is not None
        assert result.intel.policy_ids_matched == ("policy-abc-123",)


def test_amd_daemon_does_not_serve_intel_by_default():
    with MockVtpmDaemon(hwmodel=HWMODEL_AMD) as daemon:
        assert daemon.serve_intel is False
        with pytest.raises(RuntimeError, match="no Intel endpoint"):
            _ = daemon.intel_url


def test_daemon_rejects_unknown_hwmodel():
    with pytest.raises(ValueError, match="hwmodel"):
        MockVtpmDaemon(hwmodel="GCP_MYSTERY")


def test_daemon_404s_unknown_route():
    """The launcher contract has exactly two routes — anything else 404s
    (mirrors the real daemon's strict routing)."""
    import urllib.error
    import urllib.request

    with MockVtpmDaemon() as daemon:
        req = urllib.request.Request(
            f"http://127.0.0.1:{daemon.primary_port}/v1/other",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(req, timeout=5)
        assert exc_info.value.code == 404


# --- Fault injection (stateful, fail-closed) -------------------------------


def test_fault_down_503_fails_closed():
    with MockVtpmDaemon() as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url)
        run(engine.fetch_token())  # healthy first
        daemon.set_fault_mode("down")  # mid-test state mutation
        with pytest.raises(AttestationServiceUnavailableError):
            run(engine.fetch_token())
        daemon.set_fault_mode(None)  # recover
        assert run(engine.fetch_token()).swname == EXPECTED_SWNAME


def test_fault_empty_body_fails_closed():
    with MockVtpmDaemon() as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url)
        daemon.set_fault_mode("empty")
        with pytest.raises(AttestationServiceUnavailableError, match="empty body"):
            run(engine.fetch_token())


def test_fault_garbage_rejected_fails_closed():
    with MockVtpmDaemon() as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url)
        daemon.set_fault_mode("garbage")
        with pytest.raises(AttestationTokenError):
            run(engine.fetch_token())


def test_fault_slow_times_out_fails_closed():
    with MockVtpmDaemon(slow_seconds=2.0) as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url, timeout=0.3)
        daemon.set_fault_mode("slow")
        # The engine's own socket timeout (0.3s) fires first — still the
        # typed fail-closed error, never a hang or a partial result.
        with pytest.raises(AttestationServiceUnavailableError, match="unreachable"):
            run(engine.fetch_token())


# --- Genuine signing -------------------------------------------------------


def test_rs256_tokens_are_really_signed_and_verify():
    """RS256 mode: the enclave parses the token normally (signatures are
    verified by the relying party at fetch-independent time), and the token
    signature cryptographically VERIFIES against the daemon's public key."""
    with MockVtpmDaemon(signing_alg="RS256") as daemon:
        engine = AttestationEngine(endpoint=daemon.primary_url)
        token = run(engine.fetch_token())
        assert token.swname == EXPECTED_SWNAME  # enclave path unaffected
        header = json.loads(
            base64.urlsafe_b64decode(
                token.raw_token.split(".")[0] + "=="
            )
        )
        assert header["alg"] == "RS256"
        # Real signature check against the ephemeral key.
        seg = token.raw_token.split(".")
        signing_input = f"{seg[0]}.{seg[1]}".encode("ascii")
        sig = base64.urlsafe_b64decode(seg[2] + "==")
        public_key = load_pem_public_key(daemon.verifying_public_key())
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        public_key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())


# --- Unix-socket transport -------------------------------------------------


def test_unix_socket_transport_mirrors_launcher():
    """The engine's real Unix-socket path (the Confidential VM launcher
    contract) is exercised end-to-end. Platform-dependent: skipped when
    AF_UNIX is unavailable or the OS refuses the bind."""
    if not hasattr(socket, "AF_UNIX"):
        pytest.skip("AF_UNIX not available on this platform")
    socket_path = os.path.join(tempfile.gettempdir(), "mock_vtpm_teeserver.sock")
    try:
        with MockVtpmDaemon(transport="unix", socket_path=socket_path) as daemon:
            engine = AttestationEngine(
                endpoint=daemon.primary_url, socket_path=socket_path
            )
            token = run(engine.fetch_token())
            assert token.swname == EXPECTED_SWNAME
            assert token.image_digest.startswith("sha256:")
            # Cleanup contract: the socket file is removed on stop.
            assert os.path.exists(socket_path)
        assert not os.path.exists(socket_path)
    except OSError as exc:  # platform quirk — skip honestly, never fail CI
        pytest.skip(f"AF_UNIX bind/connect refused on this platform: {exc}")


# --- lifecycle --------------------------------------------------------------


def test_context_manager_stops_servers_cleanly():
    with MockVtpmDaemon() as daemon:
        url = daemon.primary_url  # capture BEFORE teardown
        engine = AttestationEngine(endpoint=url)
        assert run(engine.fetch_token()).swname == EXPECTED_SWNAME
    # After __exit__, the port is released: a fresh engine gets a
    # connection-refused (fail-closed), not a stale answer.
    with pytest.raises(AttestationServiceUnavailableError):
        run(AttestationEngine(endpoint=url).fetch_token())


def test_daemon_requires_start_for_urls():
    daemon = MockVtpmDaemon()
    with pytest.raises(RuntimeError, match="not started"):
        _ = daemon.primary_url
    with pytest.raises(RuntimeError, match="not started"):
        _ = daemon.primary_port

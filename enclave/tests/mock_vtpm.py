"""mock_vtpm.py — local Confidential Space vTPM test double (Prompt 089).

A reusable OFFLINE test double for the GCP Confidential Space tee-server
daemon, explicitly permitted by the roadmap (Prompt 089: "local vTPM mock
daemon ... for offline integration testing"). It stands in for hardware that
offline CI cannot contain — the real launcher lives only inside a
Confidential VM — while emulating the REAL contract exactly so the enclave's
actual crypto, routing, and fail-closed logic execute unmodified:

    POST http://localhost/v1/token        -> raw JWT   (Google Confidential
                                                         Space OIDC attestation)
    POST http://localhost/v1/intel/token  -> raw JWT   (Intel Trust Authority,
                                                         TDX only)
    Request body: {"audience": str, "nonces": [str], "token_type": "OIDC"}
    Response:     the raw JWT string (never a JSON wrapper)

Design (user-pro-verified research, Prompt 089):

* :class:`MockVtpmDaemon` — a context-managed daemon. Starts real HTTP
  server(s), exposes ``primary_url`` / ``intel_url``, and supports
  mid-test fault injection via :meth:`MockVtpmDaemon.set_fault_mode`
  ("down" -> HTTP 503, "slow" -> delayed response (timeout), "empty" ->
  empty body, "garbage" -> non-JWT bytes) so fail-closed paths are proven
  against a STATEFUL double, not a static stub.
* **Transport** — TCP on 127.0.0.1 by default (cross-platform, incl.
  Windows dev boxes); ``transport="unix"`` mirrors the real launcher socket
  (``/run/container_launcher/teeserver.sock``) over an AF_UNIX socket so the
  engine's real ``_UnixSocketHTTPConnection`` path is exercised.
* **Genuinely signed JWTs** — every token is really cryptographically
  signed: HS256 (RFC 7518) under a per-daemon CSPRNG key by default, or
  RS256 with an ephemeral RSA-2048 keypair (exposed via
  :meth:`MockVtpmDaemon.verifying_public_key` for future JWKS-validation
  tests). Claim shapes mirror the REAL Confidential Space token (Prompt
  085): ``image_digest`` NESTED at ``submods.container.image_digest`` and
  ``instance_id`` at ``submods.gce.instance_id`` — never the fake top-level
  shape. The enclave does not verify signatures at fetch time (the local
  socket is launcher-trusted; the relying party verifies), so the algorithm
  does not change what the enclave validates — RS256 is offered for
  realism and future relying-party tests.

Consumers: the enclave offline integration suite (enclave/tests) and
.tools/083_serve_tee.py (the Docker smoke's host-side tee servers).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import socket
import socketserver
import threading
import time
from typing import Any

# `cryptography` is a pinned enclave dependency (requirements.txt) — used
# only for the optional RS256 signing mode (real RSA signatures, no PyJWT).
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# --- Canonical contract values (mirror src.crypto.attestation) ------------

# Google Confidential Space attestation issuer.
OIDC_ISSUER = "https://confidentialcomputing.googleapis.com"
# Intel Trust Authority (ITA) token issuer.
ITA_OIDC_ISSUER = "https://portal.trustauthority.intel.com"
# The swname claim value identifying a hardened Confidential Space OS.
EXPECTED_SWNAME = "CONFIDENTIAL_SPACE"
# hwmodel values (the immutable TDX-detection signal used by the engine).
HWMODEL_AMD = "GCP_AMD_SEV"
HWMODEL_TDX = "GCP_INTEL_TDX"
# Default audience when a request omits one (matches the engine default).
DEFAULT_AUDIENCE = "flare-verifiable-rag"
# The launcher's real tee-server socket path (Confidential VM).
TEESERVER_SOCKET = "/run/container_launcher/teeserver.sock"

# Route contract served by the daemon.
TOKEN_ROUTE = "/v1/token"
INTEL_ROUTE = "/v1/intel/token"
# Supported fault-injection modes (None = healthy).
FAULT_MODES = ("down", "slow", "empty", "garbage")


def b64url(data: bytes) -> str:
    """Base64url without padding (JWT segment encoding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(claims: dict[str, Any], secret: bytes) -> str:
    """Genuinely sign claims with HS256 (RFC 7518) under the given key."""
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def primary_claims(
    *,
    audience: str,
    nonce: str,
    hwmodel: str,
    image_digest: str,
    instance_id: str | None,
    exp_offset: float,
    iat_offset: float,
) -> dict[str, Any]:
    """The REAL Confidential Space OIDC claim set (Prompt 085 shape): the
    identity claims live at the NESTED submods paths, never top-level."""
    now = time.time()
    submods: dict[str, Any] = {
        "container": {
            "image_digest": image_digest,
            "image_id": "sha256:" + "ab" * 32,
            "restart_policy": "Always",
        }
    }
    if instance_id is not None:
        submods["gce"] = {
            "instance_id": instance_id,
            "project_id": "flare-prod",
            "zone": "us-central1-a",
        }
    return {
        "iss": OIDC_ISSUER,
        "sub": "projects/flare-prod/zones/us-central1-a/instances/enclave-1",
        "aud": audience,
        "iat": int(now + iat_offset),
        "exp": int(now + exp_offset),
        "jti": secrets.token_hex(16),
        "swname": EXPECTED_SWNAME,
        "swversion": ["240500"],
        "hwmodel": hwmodel,
        "submods": submods,
        "dbgstat": "disabled-since-boot",
        "attester_tcb": ["INTEL"] if hwmodel == HWMODEL_TDX else ["AMD-SEV-SNP"],
        "google_service_accounts": ["sa@flare.iam.gserviceaccount.com"],
        "eat_nonce": nonce,
    }


def intel_claims(
    *, audience: str, nonce: str, exp_offset: float, iat_offset: float
) -> dict[str, Any]:
    """A realistic Intel Trust Authority token (Prompt 083 shape)."""
    now = time.time()
    return {
        "iss": ITA_OIDC_ISSUER,
        "sub": "projects/flare-prod/zones/us-central1-a/instances/enclave-1",
        "aud": audience,
        "iat": int(now + iat_offset),
        "exp": int(now + exp_offset),
        "swname": EXPECTED_SWNAME,
        "hwmodel": HWMODEL_TDX,
        "attester_tcb": ["INTEL"],
        "tdx": {
            "tdx_mrtd": "ab" * 48,
            "tdx_rtmr0": "cd" * 48,
            "tdx_rtmr1": "ef" * 48,
        },
        "policy_ids_matched": [{"id": "policy-abc-123"}],
        "policy_ids_unmatched": [],
        "container": {"image_reference": "ghcr.io/flare-verifiable-rag/enclave:dev"},
        "eat_nonce": nonce,
    }


class _VtpmHandler(http.server.BaseHTTPRequestHandler):
    """Serves the launcher contract: POST /v1/token and /v1/intel/token.

    ``self.server.daemon`` (set by the daemon) carries the mutable fault
    state, so fault injection works mid-test (stateful double).
    """

    def log_message(self, *args: Any) -> None:  # silence request logs
        pass

    def do_POST(self) -> None:  # noqa: N802 (http.server naming)
        daemon: MockVtpmDaemon = self.server.daemon  # type: ignore[attr-defined]
        mode = daemon.fault_mode
        if mode == "down":
            # 503 fail-closed semantic (tests proxy eviction / gate refusal).
            self.send_response(503)
            self.end_headers()
            return
        if mode == "slow":
            time.sleep(daemon.slow_seconds)  # tests the engine's timeout path
        if self.path not in (TOKEN_ROUTE, INTEL_ROUTE):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}
        audience = body.get("audience") or DEFAULT_AUDIENCE
        nonces = body.get("nonces") or ["n1"]
        if mode == "empty":
            payload = b""  # tests the engine's empty-body fail-closed path
        elif mode == "garbage":
            payload = b"not-a-jwt"  # tests malformed-token fail-closed path
        else:
            is_intel = self.path == INTEL_ROUTE
            claims = daemon._claims_for(audience, nonces[0], is_intel)
            payload = daemon._sign(claims).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except OSError:
            # Client went away (e.g. the engine's timeout fired during a
            # "slow" fault) — the daemon never crashes on a dropped peer.
            pass


class _VtpmHTTPServer(http.server.ThreadingHTTPServer):
    """TCP server carrying the daemon reference for the handler."""

    daemon: MockVtpmDaemon


# ``socketserver.UnixStreamServer`` is only defined on platforms with
# AF_UNIX (Windows lacks it entirely) — so the Unix server class is
# conditionally declared. ``None`` signals "unsupported" to start().
if hasattr(socket, "AF_UNIX"):

    class _VtpmUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        """AF_UNIX HTTP server — mirrors the launcher's real Unix socket.

        ``BaseHTTPRequestHandler`` reads/writes ``rfile``/``wfile`` which
        ``StreamRequestHandler`` provides over the connected socket, so the
        SAME handler class serves both transports.
        """

        daemon: MockVtpmDaemon
        # ThreadingMixIn defaults to non-daemon threads; daemon threads let
        # the process exit immediately even if a slow-mode handler lingers.
        daemon_threads = True

        def server_bind(self) -> None:  # clean stale socket files before binding
            if os.path.exists(self.server_address):
                os.unlink(self.server_address)
            super().server_bind()

        def get_request(self):
            request, _client = super().get_request()
            return request, ("unix", 0)

else:  # pragma: no cover — Windows build without AF_UNIX
    _VtpmUnixServer = None  # type: ignore[assignment,misc]


class MockVtpmDaemon:
    """Reusable offline vTPM test double (Prompt 089).

    Usage::

        with MockVtpmDaemon(hwmodel=HWMODEL_TDX) as daemon:
            engine = AttestationEngine(
                endpoint=daemon.primary_url, intel_endpoint=daemon.intel_url
            )
            token = await engine.fetch_token_with_fallback()

    Or start/stop manually; ``set_fault_mode`` mutates behavior mid-test.
    Every token is genuinely signed; nothing here is fabricated text.
    """

    def __init__(
        self,
        *,
        hwmodel: str = HWMODEL_AMD,
        serve_intel: bool | None = None,
        transport: str = "tcp",
        signing_alg: str = "HS256",
        audience: str = DEFAULT_AUDIENCE,
        exp_offset: float = 3600.0,
        iat_offset: float = -5.0,
        image_digest: str = "sha256:" + "cd" * 32,
        instance_id: str | None = "3507932791508176595",
        socket_path: str = TEESERVER_SOCKET,
        slow_seconds: float = 2.0,
    ) -> None:
        if hwmodel not in (HWMODEL_AMD, HWMODEL_TDX):
            raise ValueError(f"hwmodel must be {HWMODEL_AMD!r} or {HWMODEL_TDX!r}")
        if signing_alg not in ("HS256", "RS256"):
            raise ValueError("signing_alg must be 'HS256' or 'RS256'")
        if transport not in ("tcp", "unix"):
            raise ValueError("transport must be 'tcp' or 'unix'")
        self.hwmodel = hwmodel
        # TDX implies the ITA endpoint is served (the fallback is mandatory);
        # AMD serves primary-only unless explicitly requested otherwise.
        self.serve_intel = (
            hwmodel == HWMODEL_TDX if serve_intel is None else serve_intel
        )
        self.transport = transport
        self.signing_alg = signing_alg
        self.audience = audience
        self.exp_offset = exp_offset
        self.iat_offset = iat_offset
        self.image_digest = image_digest
        self.instance_id = instance_id
        self.socket_path = socket_path
        self.slow_seconds = slow_seconds
        self.fault_mode: str | None = None
        self._jwt_secret = secrets.token_bytes(32)
        self._rsa_private: rsa.RSAPrivateKey | None = None
        self._primary_server: _VtpmHTTPServer | _VtpmUnixServer | None = None
        self._intel_server: _VtpmHTTPServer | None = None
        self._threads: list[threading.Thread] = []

    # -- lifecycle --------------------------------------------------------

    def __enter__(self) -> "MockVtpmDaemon":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    def start(self) -> None:
        if self.transport == "unix":
            if not hasattr(socket, "AF_UNIX") or _VtpmUnixServer is None:
                raise RuntimeError(
                    "Unix-socket transport requested but this Python build "
                    "has no AF_UNIX support"
                )
            self._primary_server = _VtpmUnixServer(
                self.socket_path, _VtpmHandler
            )
        else:
            self._primary_server = _VtpmHTTPServer(("127.0.0.1", 0), _VtpmHandler)
        self._primary_server.daemon = self
        self._threads.append(
            threading.Thread(
                target=self._primary_server.serve_forever, daemon=True
            )
        )
        if self.serve_intel:
            self._intel_server = _VtpmHTTPServer(("127.0.0.1", 0), _VtpmHandler)
            self._intel_server.daemon = self
            self._threads.append(
                threading.Thread(
                    target=self._intel_server.serve_forever, daemon=True
                )
            )
        for t in self._threads:
            t.start()

    def stop(self) -> None:
        for server in (self._primary_server, self._intel_server):
            if server is not None:
                try:
                    server.shutdown()
                    server.server_close()
                except OSError:
                    pass
        if self.transport == "unix" and os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass
        self._primary_server = None
        self._intel_server = None
        self._threads.clear()

    def set_fault_mode(self, mode: str | None) -> None:
        """Inject a fault mid-test: 'down', 'slow', 'empty', 'garbage' or
        None (healthy). Stateful — the running server picks it up on the
        next request, so fail-closed transitions are proven live."""
        if mode is not None and mode not in FAULT_MODES:
            raise ValueError(f"fault mode must be one of {FAULT_MODES} or None")
        self.fault_mode = mode

    # -- addresses --------------------------------------------------------

    @property
    def primary_port(self) -> int:
        if self._primary_server is None:
            raise RuntimeError("daemon not started")
        if self.transport == "unix":
            return -1  # Unix transport has no TCP port; use primary_url
        return int(self._primary_server.server_address[1])  # type: ignore[index]

    @property
    def intel_port(self) -> int:
        if self._intel_server is None:
            raise RuntimeError("daemon has no Intel endpoint")
        return int(self._intel_server.server_address[1])  # type: ignore[index]

    @property
    def primary_url(self) -> str:
        if self._primary_server is None:
            raise RuntimeError("daemon not started")
        if self.transport == "unix":
            # The URL is only a label for the Unix transport — the engine
            # routes through the socket path instead.
            return "http://localhost" + TOKEN_ROUTE
        return f"http://127.0.0.1:{self.primary_port}{TOKEN_ROUTE}"

    @property
    def intel_url(self) -> str:
        return f"http://127.0.0.1:{self.intel_port}{INTEL_ROUTE}"

    def verifying_public_key(self) -> bytes:
        """PEM of the ephemeral public key when RS256 (for future JWKS /
        relying-party signature-validation tests)."""
        if self.signing_alg != "RS256" or self._rsa_private is None:
            raise RuntimeError("verifying_public_key requires signing_alg='RS256'")
        return self._rsa_private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

    # -- token production -------------------------------------------------

    def _claims_for(
        self, audience: str, nonce: str, is_intel: bool
    ) -> dict[str, Any]:
        if is_intel:
            return intel_claims(
                audience=audience,
                nonce=nonce,
                exp_offset=self.exp_offset,
                iat_offset=self.iat_offset,
            )
        return primary_claims(
            audience=audience,
            nonce=nonce,
            hwmodel=self.hwmodel,
            image_digest=self.image_digest,
            instance_id=self.instance_id,
            exp_offset=self.exp_offset,
            iat_offset=self.iat_offset,
        )

    def _sign(self, claims: dict[str, Any]) -> str:
        if self.signing_alg == "RS256":
            return self._sign_rs256(claims)
        return sign_hs256(claims, self._jwt_secret)

    def _sign_rs256(self, claims: dict[str, Any]) -> str:
        if self._rsa_private is None:
            self._rsa_private = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )
        header = {"alg": "RS256", "typ": "JWT"}
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        sig = self._rsa_private.sign(
            signing_input.encode("ascii"), padding.PKCS1v15(), crypto_hashes.SHA256()
        )
        return signing_input + "." + b64url(sig)


def run_daemon(
    *,
    ports_file: str | None = None,
    extra_files: list[str] | None = None,
    hwmodel: str = HWMODEL_TDX,
    **kwargs: Any,
) -> int:
    """Standalone launcher (used by .tools/083_serve_tee.py and CI): start a
    daemon on ephemeral TCP ports, write ``PRIMARY_PORT``/``INTEL_PORT`` to
    ``ports_file`` (and best-effort ``extra_files``), serve until interrupted."""
    daemon = MockVtpmDaemon(hwmodel=hwmodel, **kwargs)
    try:
        daemon.start()
        lines = [f"PRIMARY_PORT={daemon.primary_port}\n"]
        if daemon.serve_intel:
            lines.append(f"INTEL_PORT={daemon.intel_port}\n")
        targets = []
        if ports_file:
            targets.append(os.environ.get("TEE_PORTS_FILE", ports_file))
        targets.extend(extra_files or [])
        written = False
        for target in targets:
            try:
                with open(target, "w", encoding="utf-8") as fh:
                    fh.writelines(lines)
                written = True
            except OSError:
                pass  # best-effort: at least one target must have been written
        if written:
            print(
                f"tee servers up: primary={daemon.primary_port} "
                f"intel={daemon.intel_port}"
            )
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
    finally:
        daemon.stop()


if __name__ == "__main__":
    import sys

    ports = sys.argv[1] if len(sys.argv) > 1 else None
    raise SystemExit(run_daemon(ports_file=ports))

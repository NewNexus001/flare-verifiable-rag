"""attestation.py — Confidential Space vTPM hardware attestation engine.

Phase 5 / Prompt 081. This module implements the enclave's trust root: an
[``AttestationEngine``] that fetches the hardware attestation token from the
local Confidential Space vTPM agent and extracts the hardware measurements.

Research-backed contract (user research + google/confidential-space
launcher, 2026-08-07):

* **Endpoint** — ``http://localhost/v1/token``, served by the container
  launcher's tee server over the Unix socket
  ``/run/container_launcher/teeserver.sock``. The request is an HTTP
  **POST** with a JSON body: ``{"audience", "nonces", "token_type"}``.
  The response body is the **raw JWT string** (not a JSON wrapper).
* **Claim names** — ``swname`` (``"CONFIDENTIAL_SPACE"``), ``swversion``
  (array), ``hwmodel`` (``"GCP_AMD_SEV"`` / ``"GCP_INTEL_TDX"``),
  ``dbgstat`` (``"disabled-since-boot"`` in production), ``attester_tcb``,
  ``google_service_accounts``, plus standard OIDC ``iss``/``aud``/``iat``/
  ``exp``/``jti``/``eat_nonce``.
* **Nested claim paths (Prompt 085 research)** — ``image_digest`` lives at
  ``submods.container.image_digest`` (NOT top-level — the Google CEL
  policy form ``assertion.submods.container.image_digest``) and
  ``instance_id`` lives at ``submods.gce.instance_id`` (the CEL form
  ``assertion.submods.gce.instance_id``). ``swname``/``sub``/``aud`` are
  top-level. The nested-path extraction is canonical in ``jwt_parser.py``
  (:func:`extract_attestation_claims`) and reused here.
* **Signature verification is NOT the enclave's job at fetch time** — the
  local socket is trusted (launcher-isolated); the *relying party* (GCP
  Workload Identity Federation / STS exchange, later prompts) verifies the
  signature against the issuer's JWKS
  (``https://confidentialcomputing.googleapis.com``). This module decodes
  and validates structure, temporal validity, environment (``swname``) and
  audience — with the standard library only (no PyJWT dependency).
* **Intel Trust Authority fallback (Prompt 083)** — on Intel TDX hardware
  the launcher also serves an ITA attestation token at
  ``http://localhost/v1/intel/token`` (same Unix socket, same POST body,
  raw JWT response; ``iss=https://portal.trustauthority.intel.com``,
  ``hwmodel=GCP_INTEL_TDX``, ``attester_tcb=["INTEL"]``, TDX quote,
  Intel appraisal policy IDs). TDX is detected from the primary token's
  ``hwmodel`` claim; :meth:`AttestationEngine.fetch_token_with_fallback`
  then fetches and validates the ITA token as the independent
  third-party verifier source (research: ITA is used in addition to /
  independently of the Google attestation, for external relying parties).
  On TDX, an ITA fetch failure RAISES (fail closed) — the fallback is
  mandatory once TDX is detected.
* **Fail-closed posture** (blueprint SRE table: "vTPM Token Fetch Timeout
  → HTTP 503 Service Unavailable; denies payload decryption key load"):
  when the endpoint is unreachable (not running in Confidential Space,
  socket missing, timeout), the engine raises the typed
  [``AttestationServiceUnavailableError``] — there is NO fabricated
  measurement, NO degraded mode. Callers (the gateway) map it to 503 and
  refuse to load decryption keys.

Nothing in this module ever constructs or simulates an attestation token.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import json
import logging
import os
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from src.crypto import CryptoError, random_hex
from src.crypto.jwt_parser import (
    EXPECTED_SWNAME,  # canonical swname constant (Prompt 086) — single source
    JwtError,
    as_str_list,
    decode_jwt,
    extract_attestation_claims,
    validate_oidc_claims,
)

_logger = logging.getLogger(__name__)

# --- Confidential Space contract constants (GCP docs + launcher) -----------

# The tee server endpoint inside a Confidential Space workload container.
ATTESTATION_ENDPOINT = "http://localhost/v1/token"
# The container launcher's tee server Unix socket (real VM path).
TEESERVER_SOCKET = "/run/container_launcher/teeserver.sock"
# OIDC issuer of Confidential Space attestation tokens (relying parties
# verify signatures against its JWKS at /.well-known/openid-configuration).
OIDC_ISSUER = "https://confidentialcomputing.googleapis.com"
# Intel Trust Authority (ITA) endpoint served by the same launcher tee
# server on Intel TDX hardware (Prompt 083) — same socket, same POST body.
INTEL_TOKEN_ENDPOINT = "http://localhost/v1/intel/token"
# ITA token issuer (Intel Trust Authority portal).
ITA_OIDC_ISSUER = "https://portal.trustauthority.intel.com"
# The hwmodel value that means the workload is attested on Intel TDX — the
# trigger for the ITA fallback (research: the recommended, immutable signal).
EXPECTED_TDX_HWMODEL = "GCP_INTEL_TDX"
# The attester_tcb value that identifies the Intel hardware root of trust.
EXPECTED_TDX_TCB = ("INTEL",)
# EXPECTED_SWNAME is imported from src.crypto.jwt_parser (Prompt 086) — the
# canonical constant; this module re-exports it for backward compatibility.
# Token type requested from the tee server.
OIDC_TOKEN_TYPE = "OIDC"
# Default audience when the caller does not pin one (public identifier).
DEFAULT_AUDIENCE = "flare-verifiable-rag"
# Request/socket timeout (seconds) and temporal clock-skew tolerance.
DEFAULT_TIMEOUT_S = 5.0
CLOCK_SKEW_S = 5.0
# Default nonce length (bytes) for the per-request eat_nonce (CSPRNG).
_DEFAULT_NONCE_BYTES = 16

# image_digest canonical form: sha256:<64 lowercase hex>.
_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# hwmodel claim -> hardware family (matches main.AttestationStatusResponse).
HW_MODEL_TO_FAMILY: dict[str, str] = {
    "GCP_AMD_SEV": "AMD SEV-SNP",
    "GCP_INTEL_TDX": "Intel TDX",
}


# -- Typed errors (fail-closed; no silent fallbacks) -----------------------


class AttestationError(CryptoError):
    """Base error for all attestation failures."""


class AttestationServiceUnavailableError(AttestationError):
    """The vTPM attestation endpoint is unreachable or did not answer in
    time — the enclave is NOT running in an attested Confidential Space and
    must fail closed (HTTP 503 semantic)."""


class AttestationTokenError(AttestationError):
    """The returned token is malformed, expired, or otherwise invalid."""


class UntrustedEnvironmentError(AttestationError):
    """The token's swname claim is not CONFIDENTIAL_SPACE — the workload is
    not running in the attested environment."""


# -- JWT helpers -----------------------------------------------------------
#
# Structural decode + RFC 7519 / OIDC registered-claim validation live in
# `src.crypto.jwt_parser` (Prompt 084) — the enclave's single canonical JWT
# layer. This module keeps only the attestation-SPECIFIC checks (swname,
# image_digest, hwmodel, attester_tcb, TDX quote, nonce echo) on top of it.
# `as_str_list` is imported from there for attestation-specific claims.


# -- The attestation token model -------------------------------------------


@dataclass(frozen=True)
class AttestationToken:
    """A successfully fetched, structurally-validated attestation token.

    Only ever produced by :meth:`AttestationEngine.parse_token` after
    temporal, environment (swname), digest-format, and audience checks
    pass. The raw JWT is retained (``repr``-redacted) so a later phase can
    forward it to the GCP STS / Workload Identity exchange for signature
    verification by the relying party.
    """

    raw_token: str = field(repr=False)
    claims: Mapping[str, Any] = field(repr=False)
    swname: str
    swversion: tuple[str, ...]
    hwmodel: str | None
    image_digest: str
    instance_id: str | None
    dbgstat: str | None
    attester_tcb: tuple[str, ...]
    google_service_accounts: tuple[str, ...]
    issuer: str
    audience: str | None
    sub: str | None
    issued_at: datetime | None
    expires_at: datetime | None
    # EAT nonce echo — a string OR an array of strings (standard EAT shape,
    # Prompt 090 research); preserved raw, validated via as_str_list.
    eat_nonce: str | list[str] | None

    @property
    def hardware(self) -> str:
        """Hardware family name (unknown for unlisted hwmodel values)."""
        return HW_MODEL_TO_FAMILY.get(self.hwmodel, "unknown") if self.hwmodel else "unknown"

    @property
    def attested(self) -> bool:
        """True by construction: the token passed all validation checks."""
        return True

    def to_registration_payload(self) -> dict[str, Any]:
        """ABI-shaped payload for a ONE-TIME enclave registration call
        (Prompt 092 — research Pattern A: Phala / Flashbots
        ``registerEnclave``).

        Canonical contract interface (Phase 6, research-backed):

        .. code-block:: solidity

            function registerEnclave(
                string calldata jwtToken,
                string calldata imageDigest,
                string calldata swname,
                string calldata instanceId
            ) external;

        The raw vTPM JWT travels as a calldata string ONCE per enclave
        lifetime. The contract must EMIT it in an event for the off-chain
        relayer (research: event logs cost ~8 gas/byte vs ~625 gas/byte
        for SSTORE — never persist the token in contract storage) and mark
        the enclave verified, so subsequent transactions are signed by the
        enclave key alone (Pattern A: gas cost of attestation verification
        is paid once per enclave lifetime).
        """
        return {
            "jwtToken": self.raw_token,
            "imageDigest": self.image_digest,
            "swname": self.swname,
            "instanceId": self.instance_id or "",
        }

    def get_measurements(self) -> dict[str, Any]:
        """The hardware measurements this token attests (never fabricated)."""
        return {
            "swname": self.swname,
            "swversion": list(self.swversion),
            "hwmodel": self.hwmodel,
            "hardware": self.hardware,
            "image_digest": self.image_digest,
            "instance_id": self.instance_id,
            "dbgstat": self.dbgstat,
            "attester_tcb": list(self.attester_tcb),
            "google_service_accounts": list(self.google_service_accounts),
            "iss": self.issuer,
            "aud": self.audience,
            "sub": self.sub,
            "iat": int(self.issued_at.timestamp()) if self.issued_at else None,
            "exp": int(self.expires_at.timestamp()) if self.expires_at else None,
            "eat_nonce": self.eat_nonce,
            "attested": True,
        }

    def to_status_response(self) -> dict[str, Any]:
        """Shape compatible with ``main.AttestationStatusResponse`` (Prompt
        064): attested, swname, image_digest, hardware, token_issued_at,
        instance_id."""
        return {
            "attested": True,
            "swname": self.swname,
            "image_digest": self.image_digest,
            "hardware": self.hardware,
            "token_issued_at": (
                self.issued_at.isoformat() if self.issued_at else None
            ),
            "instance_id": self.instance_id,
        }


@dataclass(frozen=True)
class IntelAttestationToken:
    """A validated Intel Trust Authority (ITA) attestation token.

    Only ever produced by :meth:`AttestationEngine.parse_intel_token` after
    issuer (``https://portal.trustauthority.intel.com``), environment
    (``swname``), hardware (``hwmodel == GCP_INTEL_TDX``), temporal,
    audience, and nonce-echo checks pass. Carries the ITA-specific claims:
    the raw TDX quote (``tdx``), Intel appraisal policy results, and the
    GCP VM ``sub`` self-link. The raw JWT is retained (``repr``-redacted)
    for third-party relying parties that verify it against Intel's JWKS.
    """

    raw_token: str = field(repr=False)
    claims: Mapping[str, Any] = field(repr=False)
    swname: str
    hwmodel: str | None
    attester_tcb: tuple[str, ...]
    issuer: str
    audience: str | None
    sub: str | None
    issued_at: datetime | None
    expires_at: datetime | None
    # EAT nonce echo — a string OR an array of strings (standard EAT shape);
    # may also arrive as the `nonce` alias (some launcher versions).
    eat_nonce: str | list[str] | None
    tdx_quote: Any
    policy_ids_matched: tuple[str, ...]
    policy_ids_unmatched: tuple[str, ...]
    container: Any

    @property
    def attested(self) -> bool:
        """True by construction: the token passed all validation checks."""
        return True

    def get_measurements(self) -> dict[str, Any]:
        """The ITA hardware measurements this token attests (never
        fabricated; None fields are honestly absent, not filled in)."""
        return {
            "iss": self.issuer,
            "swname": self.swname,
            "hwmodel": self.hwmodel,
            "attester_tcb": list(self.attester_tcb),
            "sub": self.sub,
            "aud": self.audience,
            "iat": int(self.issued_at.timestamp()) if self.issued_at else None,
            "exp": int(self.expires_at.timestamp()) if self.expires_at else None,
            "eat_nonce": self.eat_nonce,
            "tdx_quote": self.tdx_quote,
            "policy_ids_matched": list(self.policy_ids_matched),
            "policy_ids_unmatched": list(self.policy_ids_unmatched),
            "container": self.container,
            "attested": True,
        }


@dataclass(frozen=True)
class AttestationProof:
    """Combined hardware + execution attestation record (Prompt 087).

    Binds the three components of a verifiable execution claim into ONE
    atomic record, so neither can be swapped independently (research: the
    canonical TEE+ZK envelope):

    * **vTPM token** — the validated Confidential Space OIDC JWT
      (``raw_token``, ``repr``-redacted) + its identity claims
      (``image_digest``, ``swname``, ``hardware``).
    * **Rust ZKP proof** — the halo2 proof bytes the symbolic engine
      produced (``zk_proof``) with its three public inputs
      (``public_inputs`` = H_doc, H_prompt, H_out as 32-byte LE field
      representations).
    * **binding hash** — ``SHA-256(image_digest \u2016 zk_proof \u2016
      public_inputs)`` tying the attested image to the exact proof bytes,
      so an on-chain verifier can recompute it and reject a swapped
      digest/proof pair (the research's `AttestationProofRecord` pattern).

    Only ever produced by :meth:`AttestationEngine.generate_attestation_proof`
    after the token AND the engine proof both validate — never fabricated.
    """

    raw_token: str = field(repr=False)
    image_digest: str
    swname: str
    hardware: str
    zk_proof: bytes
    public_inputs: tuple[bytes, bytes, bytes]
    binding_hash: str

    @property
    def attested(self) -> bool:
        """True by construction: both the token and the proof validated."""
        return True

    @staticmethod
    def compute_binding_hash(
        image_digest: str, zk_proof: bytes, public_inputs: tuple[bytes, bytes, bytes]
    ) -> str:
        """The canonical binding commitment (research, Prompt 087):
        ``SHA-256(image_digest \u2016 proof_bytes \u2016 public_inputs)``.

        EXACT byte order (contractual for the on-chain verifier):
        ``image_digest`` as ASCII bytes, then the raw ``zk_proof`` bytes,
        then each public input (H_doc, H_prompt, H_out) as its 32-byte LE
        field representation, concatenated in circuit order. The Solidity
        verifier MUST recompute with the identical byte order — there is no
        length-prefixing, so the order is the contract. Deterministic and
        recomputable from the same three fields — that is what makes a
        swapped digest/proof pair detectable.
        """
        digester = hashlib.sha256()
        digester.update(image_digest.encode("ascii"))
        digester.update(zk_proof)
        for p in public_inputs:
            digester.update(p)
        return digester.hexdigest()

    def to_record(self) -> dict[str, Any]:
        """The wire-ready record for the API / on-chain submission path.

        ``public_inputs`` are hex-encoded (32-byte LE field reprs) so the
        record is JSON-safe; ``zk_proof`` is base64-encoded (binary bytes).
        """
        return {
            "attested": True,
            "swname": self.swname,
            "image_digest": self.image_digest,
            "hardware": self.hardware,
            "zk_proof": base64.b64encode(self.zk_proof).decode("ascii"),
            "public_inputs": [p.hex() for p in self.public_inputs],
            "binding_hash": self.binding_hash,
        }

    def to_flare_payload(self) -> dict[str, Any]:
        """The ABI-shaped payload for the VerifiableRAG contract's
        ``submitAttestation`` call (Prompt 092 — research: ONLY the
        commitment on-chain, ONE ABI struct).

        Canonical contract interface (Phase 6, user-pro-verified research —
        bundling the fields in a struct avoids EVM Stack-Too-Deep and lets
        the interface evolve without breaking the method selector):

        .. code-block:: solidity

            struct AttestationProof {
                bytes32      bindingHash;
                bytes        zkProof;
                bytes32[3]   publicInputs;
            }
            function submitAttestation(
                AttestationProof calldata proof,
                bytes calldata payload
            ) external returns (bool);

        The returned dict keys match the ABI input names (the connector's
        ``submit_attestation`` matches payload keys to the LIVE ABI input
        names, stripping the Solidity leading underscore):

        * ``proof`` — the struct dict: ``bindingHash`` as ``0x`` + 64 hex
          (bytes32), ``zkProof`` as raw bytes (web3 6.15 ABI-encodes
          ``bytes``), ``publicInputs`` as a list of three ``0x`` + 64 hex
          32-byte LE field representations (bytes32[3]).
        * ``payload`` — the JSON-serialized execution record
          (``to_record()``) as UTF-8 bytes, so the contract can log/index
          the record it attests. Extra keys are harmless: the connector
          picks only the inputs the live ABI declares.

        The raw vTPM JWT is deliberately NOT included (research: a
        1.5-3 KB JWT in calldata costs ~24-48K gas and on-chain JWT/JSON
        verification is prohibitive — >2.5M gas without precompiles;
        production TEE systems pass the 32-byte commitment + ZK proof and
        keep the raw token for the off-chain relying party or an event
        emission, never contract storage).

        Raises :class:`ValueError` if the public inputs are not exactly
        three 32-byte field representations (defensive — they are by
        construction; the check keeps a malformed record from producing
        garbage calldata).
        """
        if len(self.public_inputs) != 3 or any(
            len(p) != 32 for p in self.public_inputs
        ):
            raise ValueError(
                "public_inputs must be exactly three 32-byte field "
                f"representations, got {[len(p) for p in self.public_inputs]}"
            )
        return {
            "proof": {
                "bindingHash": "0x" + self.binding_hash,
                "zkProof": self.zk_proof,
                "publicInputs": ["0x" + p.hex() for p in self.public_inputs],
            },
            "payload": json.dumps(
                self.to_record(), separators=(",", ":")
            ).encode("utf-8"),
        }


@dataclass(frozen=True)
class AttestationWithIntel:
    """Composite result of :meth:`AttestationEngine.fetch_token_with_fallback`.

    ``primary`` is always the validated Confidential Space OIDC token;
    ``intel`` is the validated Intel Trust Authority token when TDX was
    detected (``hwmodel == GCP_INTEL_TDX``), else None (no fallback
    needed on non-TDX hardware). On TDX the ITA fetch is mandatory — a
    failure raises instead of producing a partial result.
    """

    primary: AttestationToken
    intel: IntelAttestationToken | None = None


# -- Unix-socket HTTP transport (real Confidential Space VM) ---------------


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that dials the tee server's Unix socket instead of TCP."""

    def __init__(self, host: str, timeout: float | None, socket_path: str) -> None:
        super().__init__(host, timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


class _UnixSocketHTTPHandler(urllib.request.AbstractHTTPHandler):
    """urllib handler that routes every HTTP request through the tee socket."""

    def __init__(self, socket_path: str, timeout: float | None) -> None:
        super().__init__()
        self._socket_path = socket_path
        self._timeout = timeout

    def http_open(self, req: urllib.request.Request):
        return self.do_open(
            lambda host, timeout=None, **kw: _UnixSocketHTTPConnection(
                host, self._timeout, self._socket_path
            ),
            req,
        )


# -- The engine ------------------------------------------------------------


class AttestationEngine:
    """Fetches and validates Confidential Space vTPM hardware attestation.

    Real flow (all time-bounded, all fail-closed):

    1. POST ``{"audience", "nonces", "token_type": "OIDC"}`` to the local
       tee server — routed through the launcher Unix socket when it exists
       (the real VM), otherwise plain HTTP (local development / tests).
    2. Read the raw JWT; decode header+payload with stdlib base64url.
    3. Validate: three segments, valid JSON, numeric ``exp`` within
       ``CLOCK_SKEW_S``, ``iat`` not in the future, ``swname ==
       CONFIDENTIAL_SPACE`` (fail closed otherwise), ``image_digest`` in
       ``sha256:<64 hex>`` form, and (when pinned) ``aud`` matches the
       requested audience.
    4. Surface an [``AttestationToken``] with the hardware measurements.

    Signature verification is deliberately NOT performed here — the local
    socket is launcher-trusted; the GCP STS/WIP exchange verifies the
    signature (later phase).
    """

    def __init__(
        self,
        *,
        endpoint: str = ATTESTATION_ENDPOINT,
        intel_endpoint: str = INTEL_TOKEN_ENDPOINT,
        socket_path: str = TEESERVER_SOCKET,
        timeout: float = DEFAULT_TIMEOUT_S,
        audience: str | None = None,
        nonces: list[str] | None = None,
    ) -> None:
        self._endpoint = endpoint
        self._intel_endpoint = intel_endpoint
        self._socket_path = socket_path
        self._timeout = timeout
        self._audience = audience or DEFAULT_AUDIENCE
        # Fresh CSPRNG nonce per engine (per-request nonces are generated on
        # each fetch; this list seeds the first one and pins the expected
        # value for testing).
        self._nonces = list(nonces) if nonces else [random_hex(_DEFAULT_NONCE_BYTES)]

    # -- public API ------------------------------------------------------

    async def _fetch_raw(self, endpoint: str | None = None) -> str:
        """POST the token request, time-bounded, and return the raw JWT.

        `endpoint` defaults to the primary OIDC endpoint; the Intel
        Trust Authority fetch passes the ITA endpoint. Timeouts map to
        :class:`AttestationServiceUnavailableError` (the fail-closed
        contract); other transport failures are already mapped to the same
        typed error inside ``_fetch_raw_token``.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._fetch_raw_token, endpoint),
                timeout=self._timeout + 1.0,
            )
        except asyncio.TimeoutError as exc:
            raise AttestationServiceUnavailableError(
                f"attestation endpoint did not respond within "
                f"{self._timeout + 1.0:.1f}s (fail closed)"
            ) from exc

    async def fetch_vtpm_token(self) -> str:
        """Fetch the raw vTPM attestation JWT from the local GCP TEE server.

        Prompt 082 — the transport-only step: POST
        ``{"audience", "nonces", "token_type": "OIDC"}`` to
        ``http://localhost/v1/token`` (routed through the launcher Unix
        socket on the real VM) and return the raw JWT string. NO parsing or
        validation is performed here — use :meth:`parse_token` /
        :meth:`fetch_token` for validated results. Fail-closed: any
        transport failure raises :class:`AttestationServiceUnavailableError`;
        there is no fallback and no fabricated token.
        """
        return await self._fetch_raw()

    async def fetch_token(self) -> AttestationToken:
        """Fetch, parse, and validate the attestation token (time-bounded).

        Composes :meth:`fetch_vtpm_token` (transport) with :meth:`parse_token`
        (structure, temporal, environment, digest, audience, and nonce-echo
        validation). Raises :class:`AttestationServiceUnavailableError` on
        any transport failure (endpoint unreachable, socket missing, timeout,
        empty body) — fail closed, never a fallback.
        """
        raw = await self._fetch_raw()
        return self.parse_token(
            raw,
            expected_audience=self._audience,
            expected_nonces=tuple(self._nonces),
        )

    async def fetch_intel_token(self) -> str:
        """Fetch the raw Intel Trust Authority JWT (Prompt 083).

        Transport-only, same POST body and socket as the primary endpoint,
        targeted at ``http://localhost/v1/intel/token``. Returns the raw
        JWT string; NO parsing — use :meth:`parse_intel_token` /
        :meth:`fetch_intel_attestation` for validated results. Fail-closed:
        any transport failure raises :class:`AttestationServiceUnavailableError`.
        """
        return await self._fetch_raw(self._intel_endpoint)

    async def fetch_intel_attestation(self) -> IntelAttestationToken:
        """Fetch and validate the Intel Trust Authority attestation token.

        Composes :meth:`fetch_intel_token` (transport) with
        :meth:`parse_intel_token` (issuer, environment, hardware, temporal,
        audience, and nonce-echo validation).
        """
        raw = await self._fetch_raw(self._intel_endpoint)
        return self.parse_intel_token(
            raw,
            expected_audience=self._audience,
            expected_nonces=tuple(self._nonces),
        )

    async def fetch_token_with_fallback(self) -> AttestationWithIntel:
        """Prompt 083 — the TDX-detected Intel Trust Authority fallback.

        1. Fetch and validate the primary Confidential Space OIDC token.
        2. If ``hwmodel == GCP_INTEL_TDX`` (TDX detected via the immutable
           hardware claim), ALSO fetch and validate the ITA token from the
           Intel endpoint as the independent third-party verifier source.
        3. Non-TDX hardware: returns ``AttestationWithIntel(intel=None)`` —
           no ITA fallback exists on AMD.

        Fail-closed: on TDX, an ITA fetch/validation failure RAISES
        :class:`AttestationServiceUnavailableError` — the fallback is
        mandatory once TDX is detected; the enclave never proceeds with a
        partial or degraded attestation.
        """
        primary = await self.fetch_token()
        if not is_tdx_hardware(primary):
            return AttestationWithIntel(primary=primary, intel=None)
        intel = await self.fetch_intel_attestation()
        return AttestationWithIntel(primary=primary, intel=intel)

    async def fetch_measurements(self) -> dict[str, Any]:
        """Convenience: fetch and return the hardware measurements dict."""
        token = await self.fetch_token()
        return token.get_measurements()

    async def generate_attestation_proof(
        self, document: str, prompt: str
    ) -> AttestationProof:
        """Generate the combined hardware + execution attestation proof.

        Prompt 087 — binds the REAL vTPM attestation token, the attested
        container image digest, and a REAL Rust ZKP proof into one atomic
        record. Fail-closed at every step:

        1. **Fetch + validate the vTPM token** (structure, temporal,
           environment, digest, audience, nonce-echo) — any failure raises
           the typed error; there is no degraded path.
        2. **Run the real Rust symbolic engine** (`indexer_rs.parse_and_prove`)
           over the given document+prompt — the deterministic tokenize →
           AST → graph-match → halo2 proof pipeline. A missing wheel raises
           the same structured RuntimeError the processor raises (the FFI
           import helper is reused from ``src.rag_engine.processor``).
        3. **Bind** — ``binding_hash = SHA-256(image_digest \u2016 proof \u2016
           public_inputs)`` commits the attested image to the exact proof
           bytes (swapped digest/proof is detectable on-chain).

        The `document`/`prompt` inputs are REQUIRED because a ZK proof over
        fabricated inputs would be exactly the mock data this system
        forbids — the proof must attest a real execution.
        """
        token = await self.fetch_token()

        from src.rag_engine.processor import _import_indexer_rs

        engine = _import_indexer_rs()
        result = engine.parse_and_prove(document, prompt)
        public_inputs = (
            bytes(result["doc_hash"]),
            bytes(result["prompt_hash"]),
            bytes(result["output_hash"]),
        )
        zk_proof = bytes(result["proof"])
        binding_hash = AttestationProof.compute_binding_hash(
            token.image_digest, zk_proof, public_inputs
        )
        return AttestationProof(
            raw_token=token.raw_token,
            image_digest=token.image_digest,
            swname=token.swname,
            hardware=token.hardware,
            zk_proof=zk_proof,
            public_inputs=public_inputs,
            binding_hash=binding_hash,
        )

    # -- parsing (pure, testable) ----------------------------------------

    @staticmethod
    def parse_token(
        raw_token: str,
        *,
        expected_audience: str | None = None,
        expected_nonces: Sequence[str] | None = None,
    ) -> AttestationToken:
        """Parse and validate a raw JWT into an :class:`AttestationToken`.

        Raises :class:`AttestationTokenError` (malformed/expired/future/
        missing claims/audience mismatch) or :class:`UntrustedEnvironmentError`
        (swname mismatch) — never a partial or degraded result.
        """
        try:
            _, claims = decode_jwt(raw_token)
            claims = validate_oidc_claims(
                claims,
                expected_issuer=OIDC_ISSUER,
                expected_audience=expected_audience,
                clock_skew=CLOCK_SKEW_S,
            )
            # Prompt 085: the identity claims are extracted through the
            # CANONICAL nested-path reader (image_digest at
            # submods.container.image_digest, instance_id at
            # submods.gce.instance_id — research-verified paths). Extraction
            # is inside this try so a JwtValidationError (e.g. non-string
            # instance_id) maps to the typed AttestationTokenError.
            extracted = extract_attestation_claims(claims)
        except JwtError as exc:
            # JWT structure/registered-claim/extraction failures map to the
            # attestation typed error — never a raw JwtError escaping this
            # layer.
            raise AttestationTokenError(str(exc)) from exc

        # -- attestation-specific checks (fail closed) --------------------
        swname = extracted["swname"]
        if swname != EXPECTED_SWNAME:
            raise UntrustedEnvironmentError(
                f"swname claim is {swname!r}, expected {EXPECTED_SWNAME!r} — "
                "not a Confidential Space attestation"
            )
        image_digest = extracted["image_digest"]
        if not isinstance(image_digest, str) or not _IMAGE_DIGEST_RE.match(
            image_digest
        ):
            raise AttestationTokenError(
                "token missing or malformed image_digest claim "
                "(submods.container.image_digest expected sha256:<64 hex>)"
            )
        instance_id = extracted["instance_id"]
        sub = extracted["sub"]
        eat_nonce = claims.get("eat_nonce")
        if expected_nonces:
            echoed = as_str_list(eat_nonce)
            if not echoed or not (set(echoed) & set(expected_nonces)):
                raise AttestationTokenError(
                    "token nonce mismatch: none of the requested nonces were "
                    "echoed in eat_nonce (anti-replay check failed)"
                )
        # NumericDate values for the model (already type-validated by
        # jwt_parser's validate_oidc_claims above).
        iat = claims.get("iat")
        exp = claims.get("exp")

        def _ts(value: Any) -> datetime | None:
            return (
                datetime.fromtimestamp(value, tz=timezone.utc)
                if isinstance(value, (int, float))
                else None
            )

        return AttestationToken(
            raw_token=raw_token.strip(),
            claims=dict(claims),
            swname=str(swname),
            swversion=as_str_list(claims.get("swversion")),
            hwmodel=claims.get("hwmodel"),
            image_digest=image_digest,
            instance_id=instance_id,
            dbgstat=claims.get("dbgstat"),
            attester_tcb=as_str_list(claims.get("attester_tcb")),
            google_service_accounts=as_str_list(
                claims.get("google_service_accounts")
            ),
            issuer=str(claims.get("iss", "")),
            audience=claims.get("aud"),
            sub=sub,
            issued_at=_ts(iat),
            expires_at=_ts(exp),
            eat_nonce=claims.get("eat_nonce"),
        )

    @staticmethod
    def parse_intel_token(
        raw_token: str,
        *,
        expected_audience: str | None = None,
        expected_nonces: Sequence[str] | None = None,
    ) -> IntelAttestationToken:
        """Parse and validate an Intel Trust Authority JWT (Prompt 083).

        Research-backed validation rules (Intel TA integration guide +
        Confidential Space token-claims reference):

        * structure — three base64url segments, JSON objects;
        * issuer — ``https://portal.trustauthority.intel.com``;
        * environment — ``swname == CONFIDENTIAL_SPACE`` (fail closed:
          ITA tokens carry ``swname == "GCE"`` when TDX passes but RIM
          verification fails — that is NOT an attested Confidential Space);
        * hardware — ``hwmodel == GCP_INTEL_TDX`` (an AMD/other token
          hitting this parser is a mismatch and must fail);
        * temporal — numeric ``exp`` within ``CLOCK_SKEW_S``, ``iat`` not
          in the future;
        * audience pinning + nonce echo (anti-replay).

        Raises :class:`AttestationTokenError` or
        :class:`UntrustedEnvironmentError` — never a partial result.
        """
        try:
            _, claims = decode_jwt(raw_token)
            claims = validate_oidc_claims(
                claims,
                expected_issuer=ITA_OIDC_ISSUER,
                expected_audience=expected_audience,
                clock_skew=CLOCK_SKEW_S,
            )
        except JwtError as exc:
            raise AttestationTokenError(str(exc)) from exc

        # -- attestation-specific checks (fail closed) --------------------
        swname = claims.get("swname")
        if swname != EXPECTED_SWNAME:
            raise UntrustedEnvironmentError(
                f"ITA token swname is {swname!r}, expected {EXPECTED_SWNAME!r} "
                "— not an attested Confidential Space (RIM failed?)"
            )
        if claims.get("hwmodel") != EXPECTED_TDX_HWMODEL:
            raise AttestationTokenError(
                f"ITA token hwmodel is {claims.get('hwmodel')!r}, expected "
                f"{EXPECTED_TDX_HWMODEL!r} — an ITA token must attest Intel TDX"
            )
        tcb = as_str_list(claims.get("attester_tcb"))
        if not (set(tcb) & set(EXPECTED_TDX_TCB)):
            raise AttestationTokenError(
                f"ITA token attester_tcb is {list(tcb)!r}, expected it to "
                f"include {EXPECTED_TDX_TCB} (Intel hardware root of trust)"
            )
        if expected_nonces:
            echoed = as_str_list(claims.get("eat_nonce") or claims.get("nonce"))
            if not echoed or not (set(echoed) & set(expected_nonces)):
                raise AttestationTokenError(
                    "ITA token nonce mismatch: none of the requested nonces "
                    "were echoed (anti-replay check failed)"
                )
        iat = claims.get("iat")
        exp = claims.get("exp")

        def _ts(value: Any) -> datetime | None:
            return (
                datetime.fromtimestamp(value, tz=timezone.utc)
                if isinstance(value, (int, float))
                else None
            )

        def _id_list(value: Any) -> tuple[str, ...]:
            if isinstance(value, list):
                return tuple(
                    str(item.get("id", item)) if isinstance(item, dict) else str(item)
                    for item in value
                )
            return ()

        return IntelAttestationToken(
            raw_token=raw_token.strip(),
            claims=dict(claims),
            swname=str(swname),
            hwmodel=claims.get("hwmodel"),
            attester_tcb=as_str_list(claims.get("attester_tcb")),
            issuer=str(claims.get("iss", "")),
            audience=claims.get("aud"),
            sub=claims.get("sub"),
            issued_at=_ts(iat),
            expires_at=_ts(exp),
            eat_nonce=claims.get("eat_nonce") or claims.get("nonce"),
            tdx_quote=claims.get("tdx") or claims.get("tdquote"),
            policy_ids_matched=_id_list(claims.get("policy_ids_matched")),
            policy_ids_unmatched=_id_list(claims.get("policy_ids_unmatched")),
            container=claims.get("container"),
        )

    # -- internals -------------------------------------------------------

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Route through the launcher Unix socket on the real VM; otherwise
        use the plain TCP HTTP opener (development and local tests)."""
        # Use the launcher Unix socket only when the Python build actually
        # supports AF_UNIX AND the socket exists (the real Confidential
        # Space VM, or a local AF_UNIX test server). Both guards are
        # required: on a build without AF_UNIX, a stray file at the socket
        # path must not push us into a raw AttributeError — the fail-closed
        # contract maps every transport failure to the typed error, never a
        # crash. Otherwise fall back to plain HTTP (development only).
        if hasattr(socket, "AF_UNIX") and os.path.exists(self._socket_path):
            return urllib.request.build_opener(
                _UnixSocketHTTPHandler(self._socket_path, self._timeout)
            )
        return urllib.request.build_opener()

    def _fetch_raw_token(self, endpoint: str | None = None) -> str:
        """POST the token request and return the raw JWT body (sync; runs in
        a worker thread so the enclave event loop never blocks). `endpoint`
        defaults to the primary OIDC endpoint (the ITA fetch passes the
        Intel Trust Authority endpoint)."""
        target = endpoint or self._endpoint
        body = json.dumps(
            {
                "audience": self._audience,
                "nonces": self._nonces,
                "token_type": OIDC_TOKEN_TYPE,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            target,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        opener = self._build_opener()
        try:
            with opener.open(request, timeout=self._timeout) as resp:
                payload = resp.read().decode("utf-8").strip()
        except (
            urllib.error.URLError,
            OSError,
            TimeoutError,
            socket.timeout,  # alias of TimeoutError on 3.10+ (explicit)
            http.client.HTTPException,  # e.g. BadStatusLine from non-HTTP garbage
            # UnicodeDecodeError is a ValueError subclass: a tee server that
            # answers with non-UTF-8 garbage must fail closed as a typed
            # AttestationServiceUnavailableError — never leak a raw decode
            # crash to the caller (Prompt 095 probe: hostile endpoint served
            # b"\xff\xfe" and the raw UnicodeDecodeError escaped).
            ValueError,
        ) as exc:
            raise AttestationServiceUnavailableError(
                "vTPM attestation endpoint unreachable: "
                f"{type(exc).__name__}"
            ) from exc
        if not payload:
            raise AttestationServiceUnavailableError(
                "vTPM attestation endpoint returned an empty body"
            )
        # Contract: the response is the raw JWT string. Some launcher
        # versions wrap it as {"token": ...}; accept both, never fabricate.
        try:
            wrapped = json.loads(payload)
            if isinstance(wrapped, dict) and isinstance(wrapped.get("token"), str):
                return wrapped["token"]
        except json.JSONDecodeError:
            pass
        return payload


# -- TDX detection helper (Prompt 083) ------------------------------------


def is_tdx_hardware(token: AttestationToken) -> bool:
    """True when the attestation token attests Intel TDX hardware.

    Detection signal (research: the recommended, immutable claim):
    ``hwmodel == "GCP_INTEL_TDX"`` from the primary Confidential Space
    OIDC token. This gates the Intel Trust Authority fallback.
    """
    return token.hwmodel == EXPECTED_TDX_HWMODEL


# -- Current-attestation state cache (Prompt 088) --------------------------

# Background renewal policy: a token is refreshed when less than this
# fraction of its lifetime remains, so the cache renews BEFORE expiry and
# never hands a proxy an about-to-expire state. Poll cadence when no state
# exists yet (retry establishment) and the ceiling between scheduled
# refreshes (bounds timer wakeups — a check is a timestamp compare, never
# a network call).
REFRESH_MARGIN_FRACTION = 0.25
STATE_POLL_INTERVAL_S = 15.0
STATE_MAX_INTERVAL_S = 60.0


class AttestationStateCache:
    """In-memory CURRENT attestation state, background-refreshed (Prompt 088).

    The production state-snapshot pattern (user-pro-verified research, GCP
    Confidential Space / Nitro / Azure MAA): a status endpoint must NOT
    perform a blocking hardware quote fetch per call — vTPM quote
    generation plus the upstream attestation-service round-trip cost
    100 ms–2 s and are rate-limited, so a background loop maintains the
    current attested state and ``/v1/attestation`` reads an instantaneous
    snapshot instead.

    * ``refresh()`` — the REAL fetch (:meth:`AttestationEngine.
      fetch_token_with_fallback`), fail-closed: a failure raises but KEEPS
      the last validated state — a valid attestation is never downgraded
      by a transient refresh hiccup; it only expires via its own ``exp``.
    * ``snapshot()`` — the current state, or raises
      :class:`AttestationServiceUnavailableError` when none was ever
      established or the held token expired (the endpoint maps this to
      HTTP 503 — never 200 with ``attested=false``, so load balancers and
      blind proxies evict an unproven node).
    * ``run_refresh_loop()`` — establishes state at boot and renews before
      expiry (``REFRESH_MARGIN_FRACTION`` of the token lifetime).

    All data is REAL vTPM output; the cache holds validated token objects,
    never fabricated measurements.
    """

    def __init__(self, engine: AttestationEngine | None = None) -> None:
        self._engine = engine if engine is not None else AttestationEngine()
        self._state: AttestationWithIntel | None = None
        self._last_error: str | None = None
        # Consecutive refresh failures — drives the failure backoff so the
        # loop NEVER hammers a down endpoint at 1s (reviewer hardening,
        # Prompt 088).
        self._consecutive_failures = 0

    @property
    def engine(self) -> AttestationEngine:
        return self._engine

    @property
    def last_error(self) -> str | None:
        """The most recent background refresh failure (None when healthy)."""
        return self._last_error

    # -- scheduling ------------------------------------------------------

    def _seconds_until_expiry(self) -> float | None:
        """Seconds until the held token expires (None: no state / no exp)."""
        if self._state is None:
            return None
        expires = self._state.primary.expires_at
        if expires is None:
            return None
        return (expires - datetime.now(timezone.utc)).total_seconds()

    def _seconds_until_refresh(self) -> float:
        """Seconds until the next refresh is DUE (0 → refresh now)."""
        if self._state is None:
            return 0.0
        remaining = self._seconds_until_expiry()
        if remaining is None:
            return STATE_MAX_INTERVAL_S  # no exp claim — poll on schedule
        if remaining <= 0:
            return 0.0
        issued = self._state.primary.issued_at
        lifetime: float | None = None
        if issued is not None and self._state.primary.expires_at is not None:
            lifetime = (self._state.primary.expires_at - issued).total_seconds()
        margin = REFRESH_MARGIN_FRACTION * (
            lifetime if lifetime and lifetime > 0 else remaining
        )
        return max(0.0, remaining - margin)

    # -- the real fetch --------------------------------------------------

    async def refresh(self) -> AttestationWithIntel:
        """Fetch the REAL current attestation state (with the ITA fallback).

        Fail-closed: raises the typed error when the vTPM endpoint is
        unreachable or the token is invalid — records it in
        ``last_error`` and the PREVIOUS validated state (if any) is
        retained until it genuinely expires.
        """
        try:
            result = await self._engine.fetch_token_with_fallback()
        except AttestationError as exc:
            self._last_error = f"{type(exc).__name__}: {exc}"
            self._consecutive_failures += 1
            raise
        self._state = result
        self._last_error = None
        self._consecutive_failures = 0
        return result

    def snapshot(self) -> AttestationWithIntel:
        """The current validated attestation state (fail-closed).

        Raises :class:`AttestationServiceUnavailableError` when no state
        was ever established or the held token has EXPIRED — the caller
        maps it to HTTP 503. Never a degraded/partial state, never a
        200-with-``attested=false`` payload.
        """
        state = self._state
        if state is None:
            raise AttestationServiceUnavailableError(
                "attestation state not yet established (no valid vTPM token)"
            )
        remaining = self._seconds_until_expiry()
        if remaining is not None and remaining <= 0:
            raise AttestationServiceUnavailableError(
                "attestation token expired; refresh in progress (fail closed)"
            )
        return state

    async def run_refresh_loop(self, stop: asyncio.Event) -> None:
        """Background loop: establish the state at boot, renew before expiry.

        Runs until `stop` is set. A failed refresh logs and retries on the
        poll cadence — the loop NEVER crashes the process and NEVER
        downgrades a still-valid state. When no state exists (dev box, tee
        server down) it retries every ``STATE_POLL_INTERVAL_S``.
        """
        while not stop.is_set():
            try:
                if self._seconds_until_refresh() <= 0:
                    await self.refresh()
            except AttestationError as exc:
                # refresh() already recorded last_error — log (quietly after
                # repeated consecutive failures, reviewer hardening) and
                # continue.
                if self._consecutive_failures >= 3:
                    _logger.debug(
                        "attestation background refresh still failing: %s", exc
                    )
                else:
                    _logger.warning(
                        "attestation background refresh failed: %s", exc
                    )
            except Exception as exc:  # defensive — never kill the loop
                self._last_error = f"{type(exc).__name__}: {exc}"
                self._consecutive_failures += 1
                _logger.exception("attestation background refresh crashed")
            # Failure backoff: no state yet OR the last refresh failed → wait
            # the poll interval, never a 1s hammer against a down endpoint.
            # Otherwise sleep until the renewal deadline (capped).
            wait = (
                STATE_POLL_INTERVAL_S
                if self._state is None or self._consecutive_failures > 0
                else min(self._seconds_until_refresh(), STATE_MAX_INTERVAL_S)
            )
            wait = max(1.0, wait)
            try:
                await asyncio.wait_for(stop.wait(), timeout=wait)
            except asyncio.TimeoutError:
                pass


# -- module-level conveniences ---------------------------------------------


async def fetch_intel_token(
    *,
    endpoint: str = INTEL_TOKEN_ENDPOINT,
    socket_path: str = TEESERVER_SOCKET,
    timeout: float = DEFAULT_TIMEOUT_S,
    audience: str | None = None,
    nonces: list[str] | None = None,
) -> str:
    """Fetch the raw Intel Trust Authority token (Prompt 083).

    Module-level convenience for :meth:`AttestationEngine.fetch_intel_token`:
    POSTs the standard token request to ``http://localhost/v1/intel/token``
    (same launcher Unix socket as the primary endpoint) and returns the raw
    ITA JWT string. Fail-closed — an unreachable endpoint raises
    :class:`AttestationServiceUnavailableError`. Parsing/validation is
    deliberately NOT performed here (see
    :func:`AttestationEngine.parse_intel_token`).
    """
    engine = AttestationEngine(
        endpoint=endpoint,
        intel_endpoint=endpoint,
        socket_path=socket_path,
        timeout=timeout,
        audience=audience,
        nonces=nonces,
    )
    return await engine.fetch_intel_token()


async def generate_attestation_proof(
    document: str,
    prompt: str,
    *,
    endpoint: str = ATTESTATION_ENDPOINT,
    socket_path: str = TEESERVER_SOCKET,
    timeout: float = DEFAULT_TIMEOUT_S,
    audience: str | None = None,
    nonces: list[str] | None = None,
) -> AttestationProof:
    """Generate the combined hardware + execution attestation proof (Prompt
    087).

    Module-level convenience for
    :meth:`AttestationEngine.generate_attestation_proof`: fetches and
    validates the vTPM token from ``http://localhost/v1/token``, runs the
    REAL Rust symbolic engine over `document`+`prompt`, and binds token +
    image digest + ZK proof into one :class:`AttestationProof` with a
    recomputable binding hash. Fail-closed — an unreachable endpoint,
    invalid token, or missing engine wheel raises a typed error.
    """
    engine = AttestationEngine(
        endpoint=endpoint,
        socket_path=socket_path,
        timeout=timeout,
        audience=audience,
        nonces=nonces,
    )
    return await engine.generate_attestation_proof(document, prompt)


async def fetch_vtpm_token(
    *,
    endpoint: str = ATTESTATION_ENDPOINT,
    socket_path: str = TEESERVER_SOCKET,
    timeout: float = DEFAULT_TIMEOUT_S,
    audience: str | None = None,
    nonces: list[str] | None = None,
) -> str:
    """Fetch the raw Confidential Space vTPM attestation token (Prompt 082).

    Module-level convenience for :meth:`AttestationEngine.fetch_vtpm_token`:
    calls the local GCP TEE server at ``http://localhost/v1/token`` (routed
    through the launcher Unix socket ``/run/container_launcher/teeserver.sock``
    when present) and returns the raw JWT string. Fail-closed — a missing or
    unresponsive endpoint raises :class:`AttestationServiceUnavailableError`;
    there is no fallback and no fabricated token. Parsing/validation is
    deliberately NOT performed here (see :func:`AttestationEngine.parse_token`).
    """
    engine = AttestationEngine(
        endpoint=endpoint,
        socket_path=socket_path,
        timeout=timeout,
        audience=audience,
        nonces=nonces,
    )
    return await engine.fetch_vtpm_token()


async def submit_attestation_to_flare(
    client: Any,
    record: AttestationProof | AttestationToken,
    *,
    fn_name: str | None = None,
    value_wei: int = 0,
    private_key: str | None = None,
) -> dict[str, Any]:
    """Prompt 092 — the connection: pass a validated attestation to Flare
    through the connector client's transaction pipeline.

    Accepts either:

    * an :class:`AttestationProof` — per-transaction submission (research
      Pattern B): the 32-byte binding commitment + ZK proof + public
      inputs ride in the tx (``to_flare_payload``). Discovery of the
      ``submitAttestation`` function is automatic (name contains
      "attest").
    * an :class:`AttestationToken` — one-time enclave registration
      (research Pattern A): the raw JWT is passed once and the contract
      emits it (``to_registration_payload``). Pass the explicit
      ``fn_name`` (e.g. ``"registerEnclave"``) — that name does not
      contain "attest", so it is not auto-discoverable.

    The payload is handed to ``FlareCoston2Client.submit_attestation``,
    which performs the FULL live pipeline (Prompt 070): registry resolve of
    the VerifiableRAG contract, live verified-ABI fetch from the Coston2
    explorer, payload-to-ABI argument matching, EIP-1559 transaction
    build, enclave-key signing, broadcast, and receipt wait.

    The client is passed in (never constructed here) so the caller owns
    its lifecycle; it is imported lazily inside for type/documentation
    only, keeping the connector module decoupled from this one. Returns
    the receipt dict from the client. Fail-closed: any registry / ABI /
    signing / network failure raises the connector's typed
    ``FlareClientError`` (e.g. :class:`ContractResolveError` while
    VerifiableRAG is not yet deployed in Phase 6) — never a fabricated
    transaction. Raises :class:`TypeError` for any other record type.
    """
    if isinstance(record, AttestationProof):
        payload = record.to_flare_payload()
    elif isinstance(record, AttestationToken):
        payload = record.to_registration_payload()
    else:
        raise TypeError(
            "record must be an AttestationProof or AttestationToken, "
            f"got {type(record).__name__}"
        )
    return await client.submit_attestation(
        payload,
        fn_name=fn_name,
        value_wei=value_wei,
        private_key=private_key,
    )


__all__ = [
    "ATTESTATION_ENDPOINT",
    "AttestationEngine",
    "AttestationError",
    "AttestationProof",
    "AttestationServiceUnavailableError",
    "AttestationStateCache",
    "AttestationToken",
    "AttestationTokenError",
    "CLOCK_SKEW_S",
    "DEFAULT_AUDIENCE",
    "DEFAULT_TIMEOUT_S",
    "EXPECTED_SWNAME",
    "EXPECTED_TDX_HWMODEL",
    "EXPECTED_TDX_TCB",
    "HW_MODEL_TO_FAMILY",
    "INTEL_TOKEN_ENDPOINT",
    "ITA_OIDC_ISSUER",
    "IntelAttestationToken",
    "AttestationWithIntel",
    "OIDC_ISSUER",
    "TEESERVER_SOCKET",
    "UntrustedEnvironmentError",
    "fetch_intel_token",
    "fetch_vtpm_token",
    "generate_attestation_proof",
    "is_tdx_hardware",
    "submit_attestation_to_flare",
]

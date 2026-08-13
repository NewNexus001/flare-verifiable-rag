"""Client-payload encryption/decryption for the enclave's secure proxy path.

Phase 4 / Prompt 072. The enclave is a **bidirectional secure gateway**: the
Next.js blind proxy is untrusted and must never see plaintext. This module
implements both directions of the client-payload AES-GCM-256 contract, built
ENTIRELY on the `crypto` package primitives (Prompt 071) — no duplicated
crypto, one source of truth for framing and key handling.

Wire format (research + 066/071-verified, matches processor.py's contract):
    envelope = nonce(12) || ciphertext || tag(16)
    plaintext (inbound) = UTF-8 JSON {"document": str, "prompt": str}
    AAD (inbound)       = crypto.AES_GCM_AAD  (protocol-version binding)
    key                 = ENCLAVE_PAYLOAD_KEY env (hex, 32 bytes, scrubbable)

Directions (user-research: "the enclave is not just a decryption sink; it is
a secure bidirectional gateway"):

* **INBOUND (client -> enclave)** — `decrypt_payload` / `decrypt_bytes` /
  `proxy_decrypted`. The gateway decrypts the client's ciphertext, validates
  it strictly (exact `{document, prompt}` schema, size caps), and hands the
  plaintext onward as a **mutable scrubbable `bytearray`** that is zeroed the
  moment its job is done (and on every exception path).

* **OUTBOUND (enclave -> client)** — `encrypt_response`. The RAG response is
  encrypted INSIDE the enclave so the blind proxy can forward only
  ciphertext. The AAD binds protocol version + per-request context
  (research AAD schema: ProtocolVersion | EndpointURI | SessionID |
  Sequence) — a response bound to one request context cannot be decrypted
  under another (context-swap / replay hardening).

Security posture (OWASP Cryptographic Storage Cheat Sheet; TEE engineering
patterns from Confidential Space / Nitro Enclaves writeups):

* Fresh 12-byte CSPRNG nonce on EVERY encrypt — nonce reuse with the same
  key would leak plaintext XOR (the GCM death knell). The 96-bit random
  space makes session tracking unnecessary; never reuse.
* Decrypt-then-VALIDATE, never decrypt-then-trust: GCM tag success only
  proves authorship + integrity; the payload is still schema-checked
  strictly (extra fields rejected).
* No plaintext/key logging: all failures raise typed CryptoError subclasses;
  nothing sensitive is written to stdout/stderr by this module.
* Key lifecycle: loaded from `ENCLAVE_PAYLOAD_KEY` (or injected), held as a
  scrubbable `bytearray`, released with `scrub()`; the returned plaintext is
  zeroed via `ctypes.memset` (C-level wipe).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from src.crypto import (
    AES_GCM_AAD,
    CryptoError,
    DecryptionError,
    GCM_MIN_WIRE_LEN,
    KeyConfigError,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    load_hex_key,
    zeroize,
)

# Environment variable holding the 32-byte client-payload key (hex). Same
# variable processor.py reads (Prompt 066) — ONE key for the whole envelope
# contract, documented in REAL-DATA-SOURCES.md.
ENCLAVE_PAYLOAD_KEY_ENV = "ENCLAVE_PAYLOAD_KEY"

# Hard cap on an inbound encrypted envelope (bytes). Mirrors
# processor.py's MAX_ENCRYPTED_PAYLOAD_BYTES exactly — a payload that
# processor would reject must be rejected here too, before any crypto work
# (bounds per-request cost inside the memory-constrained TEE).
MAX_ENCRYPTED_PAYLOAD_BYTES = 4 * 1024 * 1024  # 4 MiB

# Hard cap on one client text field (document/prompt), mirroring
# processor.py's DecryptedPayload Field(max_length=...) so the strict
# schema accepts exactly what the processor accepts.
MAX_CLIENT_TEXT_BYTES = 4 * 1024 * 1024  # 4 MiB

# Separator for the composed outbound AAD (research schema:
# ProtocolVersion | EndpointURI | SessionID | Sequence).
_AAD_SEPARATOR = b"|"


class PayloadCipherError(CryptoError):
    """Base error for the client-payload proxy layer."""


class PayloadKeyError(PayloadCipherError):
    """The client-payload key is missing, malformed, or unusable."""


class PayloadFormatError(PayloadCipherError):
    """A payload envelope or its decrypted content violates the contract."""


@dataclass(frozen=True)
class DecryptedClientPayload:
    """The strictly-validated inbound client payload.

    `document` / `prompt` are the parsed fields; the raw plaintext is held
    as a mutable `bytearray` (`_plaintext`) so callers can wipe it the
    moment the engine has consumed it. Use `.scrub()`, or `with` the object
    to guarantee scrubbing on exit (including exceptions).
    """

    document: str
    prompt: str
    _plaintext: bytearray = field(repr=False, compare=False)

    def scrub(self) -> None:
        """Overwrite the raw plaintext buffer with zeroes."""
        zeroize(self._plaintext)

    def __enter__(self) -> "DecryptedClientPayload":
        return self

    def __exit__(self, *exc) -> None:
        self.scrub()


_T = TypeVar("_T")


class ClientPayloadCipher:
    """Bidirectional AES-GCM-256 client-payload cipher for the enclave proxy.

    Holds the 32-byte key as a scrubbable `bytearray` (loaded from
    `ENCLAVE_PAYLOAD_KEY` unless injected), encrypts/decrypts the
    `nonce(12) || ciphertext || tag(16)` envelope, and guarantees that
    decrypted plaintext is delivered as a mutable buffer that can be (and
    by default is) zeroed immediately after use.
    """

    def __init__(self, key: bytes | bytearray | None = None) -> None:
        """Load the key from `ENCLAVE_PAYLOAD_KEY` or use an injected one.

        No default, no fallback, no hardcoded bytes (verified-data policy): the
        enclave refuses to operate without a configured key. The key is
        copied into a scrubbable `bytearray` so `scrub()` can wipe it.
        """
        if key is None:
            try:
                self._key = load_hex_key(ENCLAVE_PAYLOAD_KEY_ENV)
            except KeyConfigError as exc:
                raise PayloadKeyError(str(exc)) from exc
        else:
            # One scrubbable copy of the injected key (no double copy).
            key_ba = bytearray(key)
            if len(key_ba) != 32:
                raise PayloadKeyError(
                    f"client-payload key must be exactly 32 bytes, got {len(key_ba)}"
                )
            self._key = key_ba

    # -- inbound: client -> enclave -------------------------------------

    def decrypt_bytes(
        self, envelope: bytes, *, aad: bytes = AES_GCM_AAD
    ) -> bytearray:
        """Decrypt an inbound envelope into a scrubbable plaintext buffer.

        Validates the envelope framing (length caps) BEFORE any crypto work.
        Raises :class:`PayloadFormatError` on framing violations and
        :class:`DecryptionError` on failed authentication (tamper / wrong
        key / wrong AAD).
        """
        self._check_envelope(envelope)
        return decrypt_aes_gcm(self._key, envelope, aad)

    def decrypt_payload(self, envelope: bytes) -> DecryptedClientPayload:
        """Decrypt + strictly validate the inbound client payload.

        Schema contract (matches processor.py's `DecryptedPayload`):
        exactly `{"document": str, "prompt": str}`, both non-empty; any
        extra field, missing field, or non-string value is rejected. The
        raw plaintext buffer is zeroed if validation fails.
        """
        plain_ba = self.decrypt_bytes(envelope)
        try:
            document, prompt = self._parse_payload(plain_ba)
        except Exception:
            zeroize(plain_ba)
            raise
        return DecryptedClientPayload(
            document=document, prompt=prompt, _plaintext=plain_ba
        )

    def proxy_decrypted(
        self, envelope: bytes, consumer: Callable[[bytearray], _T]
    ) -> _T:
        """Decrypt and hand the scrubbable plaintext to `consumer`, then
        guarantee the buffer is zeroed when `consumer` returns (or raises).

        This is the enclave's proxying path: decrypted client data reaches
        the in-process engine as a mutable buffer and never outlives the
        callback. The buffer is wiped on success AND on exception.
        """
        plain_ba = self.decrypt_bytes(envelope)
        try:
            return consumer(plain_ba)
        finally:
            zeroize(plain_ba)

    # -- outbound: enclave -> client ------------------------------------

    @staticmethod
    def compose_aad(context: bytes | str = b"") -> bytes:
        """Compose the outbound AAD: protocol version + request context.

        Research schema: ``ProtocolVersion | EndpointURI | SessionID |
        Sequence``. Here the protocol-version prefix is
        ``crypto.AES_GCM_AAD`` (the established wire contract) and
        `context` carries the per-request binding (endpoint/session/seq).
        A response encrypted with one context cannot be decrypted under
        another — context-swap / replay hardening.

        `context` is CALLER-CONTROLLED and may itself contain ``|``
        separators (e.g. ``"/api/v1/query|sess_abc|seq_004"``) — that is
        by design: the FULL composed byte string is what gets bound, so
        ``P|a|b`` can never equal ``P|c`` for distinct contexts (no
        collision, no ambiguity). Callers own the entire context string.
        """
        if isinstance(context, str):
            context = context.encode("utf-8")
        return AES_GCM_AAD + _AAD_SEPARATOR + context

    def encrypt_response(
        self, plaintext: bytes, *, context: bytes | str = b""
    ) -> bytes:
        """Encrypt the enclave's outbound response for the blind proxy.

        Runs INSIDE the TEE so the Next.js proxy only ever forwards
        ciphertext (research: the enclave is a bidirectional gateway).
        Returns ``nonce(12) || ciphertext || tag(16)`` bound to
        `context` via :meth:`compose_aad`.
        """
        self._check_plaintext(plaintext)
        return encrypt_aes_gcm(self._key, plaintext, self.compose_aad(context))

    def decrypt_response(
        self, envelope: bytes, *, context: bytes | str = b""
    ) -> bytearray:
        """Symmetric decrypt of an outbound response (verification paths).

        Enforces the SAME envelope framing caps as the inbound path
        (reviewer finding, Prompt 072): without the cap check here, an
        oversized attacker-supplied envelope would be fully copied by
        `decrypt_aes_gcm` (`bytearray(payload)`), risking unbounded memory
        allocation inside the memory-constrained TEE.
        """
        self._check_envelope(envelope)
        return decrypt_aes_gcm(self._key, envelope, self.compose_aad(context))

    # -- client-side framing helper -------------------------------------

    def encrypt_payload(self, document: str, prompt: str) -> bytes:
        """Produce the EXACT inbound envelope a conforming client sends.

        Same framing, same protocol AAD, same strict field contract — so
        test tooling and (future) parity checks can speak the wire contract
        byte-for-byte. Validates both fields before encrypting.
        """
        self._check_text_field("document", document)
        self._check_text_field("prompt", prompt)
        plaintext = json.dumps(
            {"document": document, "prompt": prompt},
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        if len(plaintext) > MAX_ENCRYPTED_PAYLOAD_BYTES - GCM_MIN_WIRE_LEN:
            raise PayloadFormatError(
                f"client payload plaintext of {len(plaintext)} bytes exceeds "
                f"the {MAX_ENCRYPTED_PAYLOAD_BYTES - GCM_MIN_WIRE_LEN}-byte cap"
            )
        return encrypt_aes_gcm(self._key, plaintext, AES_GCM_AAD)

    def encrypt_bytes(
        self, plaintext: bytes, *, aad: bytes = AES_GCM_AAD
    ) -> bytes:
        """Raw symmetric encrypt into the ``nonce||ct+tag`` envelope."""
        self._check_plaintext(plaintext)
        return encrypt_aes_gcm(self._key, plaintext, aad)

    # -- lifecycle ------------------------------------------------------

    def scrub(self) -> None:
        """Overwrite the held key with zeroes (release it after use)."""
        zeroize(self._key)

    # -- internals ------------------------------------------------------

    @staticmethod
    def _check_envelope(envelope: bytes) -> None:
        if not isinstance(envelope, (bytes, bytearray, memoryview)):
            raise PayloadFormatError(
                f"envelope must be bytes-like, got {type(envelope).__name__}"
            )
        if len(envelope) < GCM_MIN_WIRE_LEN:
            raise PayloadFormatError(
                f"envelope too short: need nonce(12) + tag(16), got {len(envelope)} bytes"
            )
        if len(envelope) > MAX_ENCRYPTED_PAYLOAD_BYTES:
            raise PayloadFormatError(
                f"envelope of {len(envelope)} bytes exceeds the "
                f"{MAX_ENCRYPTED_PAYLOAD_BYTES}-byte cap"
            )

    @staticmethod
    def _check_plaintext(plaintext: bytes) -> None:
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise PayloadFormatError(
                f"plaintext must be bytes-like, got {type(plaintext).__name__}"
            )
        if len(plaintext) > MAX_ENCRYPTED_PAYLOAD_BYTES - GCM_MIN_WIRE_LEN:
            raise PayloadFormatError(
                f"plaintext of {len(plaintext)} bytes exceeds the "
                f"{MAX_ENCRYPTED_PAYLOAD_BYTES - GCM_MIN_WIRE_LEN}-byte cap"
            )

    @staticmethod
    def _check_text_field(name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip():
            raise PayloadFormatError(f"client payload '{name}' must be a non-empty string")
        if len(value.encode("utf-8")) > MAX_CLIENT_TEXT_BYTES:
            raise PayloadFormatError(
                f"client payload '{name}' exceeds the {MAX_CLIENT_TEXT_BYTES}-byte cap"
            )

    @staticmethod
    def _parse_payload(plain_ba: bytearray) -> tuple[str, str]:
        try:
            obj = json.loads(plain_ba.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PayloadFormatError(
                "client payload is not valid UTF-8 JSON"
            ) from exc
        if not isinstance(obj, dict) or set(obj) != {"document", "prompt"}:
            raise PayloadFormatError(
                "client payload must be exactly {document, prompt} "
                "(extra/missing fields rejected)"
            )
        document, prompt = obj["document"], obj["prompt"]
        ClientPayloadCipher._check_text_field("document", document)
        ClientPayloadCipher._check_text_field("prompt", prompt)
        return document, prompt


# -- module-level conveniences -------------------------------------------


def get_client_payload_cipher() -> ClientPayloadCipher:
    """Construct a cipher bound to `ENCLAVE_PAYLOAD_KEY` (FastAPI-friendly)."""
    return ClientPayloadCipher()


def encrypt_client_payload(
    document: str, prompt: str, *, key: bytes | bytearray | None = None
) -> bytes:
    """Module-level inbound envelope producer (client-side tooling)."""
    return ClientPayloadCipher(key).encrypt_payload(document, prompt)


def decrypt_client_payload(
    envelope: bytes, *, key: bytes | bytearray | None = None
) -> DecryptedClientPayload:
    """Module-level inbound envelope consumer (gateway handlers)."""
    return ClientPayloadCipher(key).decrypt_payload(envelope)


__all__ = [
    "AES_GCM_AAD",
    "ClientPayloadCipher",
    "DecryptedClientPayload",
    "ENCLAVE_PAYLOAD_KEY_ENV",
    "MAX_CLIENT_TEXT_BYTES",
    "MAX_ENCRYPTED_PAYLOAD_BYTES",
    "PayloadCipherError",
    "PayloadFormatError",
    "PayloadKeyError",
    "decrypt_client_payload",
    "encrypt_client_payload",
    "get_client_payload_cipher",
]

"""crypto — shared cryptographic helper utilities for the secure enclave.

Phase 4 / Prompt 071. One canonical home for every cryptographic primitive
the enclave uses, so `processor.py`, `main.py`, and the blockchain connector
never reimplement crypto inline (code-reuse rule). Verified against the
`cryptography` 42.0.5 wheel installed in the enclave venv (requirements.txt)
and the `web3` stack already in use.

Scope (research-backed — cryptography.io AEAD docs, OWASP cheat sheets,
PEP 506 `secrets`):

* **AES-GCM-256 AEAD helpers** — strict 32-byte key validation, fresh
  12-byte nonce from a CSPRNG per encryption, AAD support, the standard
  ``nonce(12) || ciphertext+tag`` wire format, and constant-time tag
  verification inside the library (tampered input surfaces the typed
  :class:`DecryptionError`, never a panic).
* **Secure randomness** — ``os.urandom`` for raw key/nonce material and
  ``secrets.token_hex`` for formatted tokens (both CSPRNG-backed; PEP 506 —
  the ``random`` module is never used for anything security-relevant).
* **SHA-256** — raw bytes internally, hex at API boundaries (the
  research-backed convention: bytes for crypto, hex for configuration and
  API payloads).
* **Constant-time comparison** — ``hmac.compare_digest`` (the standard
  timing-side-channel mitigation) for tags, HMACs, and secrets.
* **Zeroization** — mutable ``bytearray`` + ``ctypes.memset`` (the C-level
  wipe the cryptography docs recommend), the professional Python scrubbing
  pattern. Ported from the pattern introduced in `processor.py` (Prompt
  067); processor's private copies are intentionally left in place (its 067
  scrubbing PoW harness instruments them) and consolidation onto this
  package is a tracked follow-up.
* **Best-effort page locking** — ``mlock(2)`` + ``MADV_WIPEONFORK`` on
  Linux (silently no-ops elsewhere).
* **Base64 URL-safe** helpers for wire tokens (``-``/``_``, padding
  stripped — safe in URLs and headers).

Deliberately absent anti-patterns: no ECB or unauthenticated CBC, no nonce
reuse (every :func:`encrypt_aes_gcm` draws a fresh nonce), no hand-rolled
primitives (everything delegates to the vetted `cryptography` library), no
secrets near the predictable ``random`` module, no hardcoded keys or
fallbacks (zero-mock policy — keys come from the environment).

Environment contract: key material is injected as environment variables
(``ENCLAVE_PAYLOAD_KEY``, ``ENCLAVE_ATTESTER_KEY`` — documented in
REAL-DATA-SOURCES.md). Nothing here writes a key to disk.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import hashlib
import hmac
import os
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -- Parameter constants (NIST SP 800-38D) --------------------------------

# AES-GCM-256 key length: 32 bytes (256 bits).
GCM_KEY_LEN = 32
# Canonical GCM nonce length: 96 bits (12 bytes) — the cryptography docs
# and NIST recommend 96-bit nonces for performance and security.
GCM_NONCE_LEN = 12
# Authentication tag length: 128 bits (16 bytes), appended to the ciphertext
# by the AESGCM implementation.
GCM_TAG_LEN = 16
# Minimum wire payload: nonce(12) + tag(16) — anything shorter cannot carry
# a valid AEAD envelope.
GCM_MIN_WIRE_LEN = GCM_NONCE_LEN + GCM_TAG_LEN

# Protocol-level Additional Authenticated Data. Binding a fixed protocol tag
# into the AEAD means a payload encrypted for one protocol revision cannot
# be replayed into another (context-swap hardening). This is the exact AAD
# `processor.py` uses for the client payload envelope — it is part of the
# wire contract: the client MUST encrypt with this same AAD.
AES_GCM_AAD = b"flare-verifiable-rag:enclave:v1"

# Linux madvise(2) flag: child processes inherit ZEROED pages instead of
# copy-on-write copies of sensitive memory (Linux >= 4.14). Best-effort.
_MADV_WIPEONFORK = 18


# -- Typed errors ---------------------------------------------------------


class CryptoError(Exception):
    """Base error for all crypto helper failures."""


class KeyConfigError(CryptoError):
    """A key loaded from the environment is missing or malformed."""


class DecryptionError(CryptoError):
    """AES-GCM decryption failed (tampered payload, wrong key, or bad AAD)."""


class EncodingError(CryptoError):
    """Base64/hex encode or decode failure (typed, never a raw stdlib error)."""


# -- Secure randomness ----------------------------------------------------


def random_bytes(n: int) -> bytes:
    """`n` cryptographically-secure random bytes (CSPRNG-backed)."""
    if n < 0:
        raise ValueError("length must be non-negative")
    return os.urandom(n)


def random_hex(nbytes: int) -> str:
    """`2*nbytes` hex chars from a CSPRNG (`secrets.token_hex`, PEP 506)."""
    return secrets.token_hex(nbytes)


def generate_aes256_key() -> bytes:
    """A fresh random 256-bit AES key (cryptography library's generator)."""
    return AESGCM.generate_key(bit_length=256)


# -- AES-GCM-256 ----------------------------------------------------------


def validate_aes_key(key: Any) -> bytes:
    """Return `key` as `bytes` if it is a valid AES-256 key, else raise
    :class:`KeyConfigError`."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise KeyConfigError(
            f"AES key must be bytes-like, got {type(key).__name__}"
        )
    key_bytes = bytes(key)
    if len(key_bytes) != GCM_KEY_LEN:
        raise KeyConfigError(
            f"AES-256 key must be exactly {GCM_KEY_LEN} bytes, got {len(key_bytes)}"
        )
    return key_bytes


def encrypt_aes_gcm(
    key: Any, plaintext: bytes, aad: bytes = AES_GCM_AAD
) -> bytes:
    """AES-GCM-256 encrypt; returns ``nonce(12) || ciphertext || tag``.

    A fresh 12-byte nonce is drawn from the CSPRNG on EVERY call — nonce
    reuse with the same key would destroy confidentiality (the GCM killer).
    `aad` is authenticated but not encrypted; it must be identical at
    decryption time.
    """
    key_bytes = validate_aes_key(key)
    nonce = os.urandom(GCM_NONCE_LEN)
    ciphertext_with_tag = AESGCM(key_bytes).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext_with_tag


def decrypt_aes_gcm(
    key: Any, payload: bytes, aad: bytes = AES_GCM_AAD
) -> bytearray:
    """AES-GCM-256 decrypt of ``nonce(12) || ciphertext || tag``.

    Returns a MUTABLE ``bytearray`` of plaintext so callers can zero it in
    place immediately after use (Prompt 067 scrubbing pattern). The
    ciphertext is processed from ONE mutable working copy (memoryview views
    into a bytearray) that is zeroed in a `finally` — wiped on success AND
    on authentication failure. Tag verification happens inside the library
    in constant time; any tampering raises :class:`DecryptionError`.
    """
    key_bytes = validate_aes_key(key)
    if len(payload) < GCM_MIN_WIRE_LEN:
        raise DecryptionError(
            f"AES-GCM payload too short: need nonce({GCM_NONCE_LEN}) + "
            f"tag({GCM_TAG_LEN}), got {len(payload)} bytes"
        )
    work = bytearray(payload)  # the ONLY ciphertext copy
    try:
        view = memoryview(work)
        aesgcm = AESGCM(key_bytes)
        plaintext = aesgcm.decrypt(view[:GCM_NONCE_LEN], view[GCM_NONCE_LEN:], aad)
        # Mutable plaintext for in-place scrubbing; drop the immutable bytes
        # the library returned immediately.
        plain_bytes = bytearray(plaintext)
        del plaintext
        return plain_bytes
    except InvalidTag as exc:
        raise DecryptionError(
            "AES-GCM authentication failed: tampered ciphertext, wrong key, "
            "or mismatched AAD"
        ) from exc
    finally:
        zeroize(work)  # scrub the nonce+ciphertext working copy


# -- Zeroization / page locking (moved from processor.py, Prompt 067) -----


def zeroize(buf: bytearray) -> None:
    """Overwrite a mutable buffer with zeroes (mitigates RAM remanence).

    Uses ``ctypes.memset`` — the C-level wipe the cryptography docs
    recommend (faster and more thorough than a Python loop). `bytearray`
    exposes its buffer to ctypes, which is exactly why the enclave stores
    sensitive material in `bytearray` rather than immutable `str`/`bytes`.
    No-op on an empty buffer; strict about the type (a non-mutable value
    cannot be wiped, so it is refused rather than silently skipped).
    """
    if not isinstance(buf, bytearray):
        raise TypeError("zeroize() requires a mutable bytearray")
    if not buf:
        return
    ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
    ctypes.memset(ptr, 0, len(buf))


def lock_pages(buf: bytearray) -> None:
    """Best-effort pin of a sensitive buffer to physical RAM (Linux only).

    Uses ``mlock(2)`` (keeps pages out of swap) and ``madvise(2)`` with
    ``MADV_WIPEONFORK`` (child processes inherit zeroed pages). Silently
    no-ops on non-Linux platforms and on any failure (e.g. low
    ``RLIMIT_MEMLOCK``), because :func:`zeroize` remains the primary
    scrubbing mechanism — locking is defense-in-depth, never a correctness
    requirement.
    """
    if os.name != "posix" or not isinstance(buf, bytearray) or not buf:
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        libc.mlock(ctypes.c_void_p(addr), len(buf))
        libc.madvise(ctypes.c_void_p(addr), len(buf), _MADV_WIPEONFORK)
    except (OSError, AttributeError, ValueError):
        pass  # best-effort only; scrubbing still happens via zeroize()


# -- Hashing --------------------------------------------------------------


def sha256(data: bytes, *, hex_output: bool = False) -> bytes | str:
    """SHA-256 digest of `data` (raw bytes by default, hex if requested).

    Strict about input: `data` must already be `bytes` (callers encode
    text explicitly), enforcing the bytes-internally / hex-at-the-API
    convention.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"sha256() requires bytes-like data, got {type(data).__name__}")
    digest = hashlib.sha256(data).digest()
    return digest.hex() if hex_output else digest


def sha256_hex(data: bytes) -> str:
    """SHA-256 digest as 64 lowercase hex chars (the Sha256Hex API form)."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"sha256_hex() requires bytes-like data, got {type(data).__name__}"
        )
    return hashlib.sha256(data).hexdigest()


# -- Constant-time comparison ---------------------------------------------


def constant_time_compare(a: Any, b: Any) -> bool:
    """Constant-time comparison of two byte-like / str values.

    Delegates to ``hmac.compare_digest`` — the standard timing-side-channel
    mitigation. Use for authentication tags, HMACs, API keys, and any other
    secret equality check (never ``==`` on secrets). Mixed str/bytes
    arguments are normalized (str is UTF-8 encoded) so callers cannot trip
    `compare_digest`'s strict same-type requirement by accident; anything
    else raises the typed :class:`CryptoError`.
    """
    if isinstance(a, str) and isinstance(b, (bytes, bytearray, memoryview)):
        a = a.encode("utf-8")
    elif isinstance(b, str) and isinstance(a, (bytes, bytearray, memoryview)):
        b = b.encode("utf-8")
    try:
        return hmac.compare_digest(a, b)
    except TypeError as exc:
        raise CryptoError(
            "constant_time_compare() requires str or bytes-like arguments, "
            f"got {type(a).__name__} and {type(b).__name__}"
        ) from exc


# -- Wire encoding --------------------------------------------------------


def urlsafe_b64encode(data: bytes) -> str:
    """URL-safe base64 WITHOUT padding (safe in URLs and headers)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def urlsafe_b64decode(value: str) -> bytes:
    """Decode URL-safe base64, tolerating missing padding (round-trips
    :func:`urlsafe_b64encode` output). Invalid input raises the typed
    :class:`EncodingError` instead of leaking a raw stdlib exception.
    """
    if not isinstance(value, str):
        raise EncodingError(
            f"urlsafe_b64decode() requires str, got {type(value).__name__}"
        )
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise EncodingError(f"invalid URL-safe base64 input: {exc}") from exc


# -- Environment key loading ----------------------------------------------


def load_hex_key(env_var: str, *, expected_len: int = GCM_KEY_LEN) -> bytearray:
    """Load a hex key from `env_var` as a SCRUBBABLE ``bytearray``.

    No default, no fallback, no hardcoded bytes (zero-mock policy): the
    enclave refuses to operate without the configured key. Accepts an
    optional ``0x`` prefix (tolerated, stripped) and any hex-letter case.
    Returns a mutable ``bytearray`` specifically so callers can
    :func:`zeroize` it immediately after use.

    Raises :class:`KeyConfigError` if the variable is missing or does not
    decode to exactly `expected_len` bytes.
    """
    raw = os.environ.get(env_var)
    if not raw:
        raise KeyConfigError(f"{env_var} is not set: cannot load key material")
    hex_str = raw.strip()
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    try:
        key = bytearray.fromhex(hex_str)
    except ValueError as exc:
        raise KeyConfigError(
            f"{env_var} must be hex text ({expected_len * 2} chars), got {raw!r}"
        ) from exc
    if len(key) != expected_len:
        raise KeyConfigError(
            f"{env_var} must decode to exactly {expected_len} bytes, got {len(key)}"
        )
    return key


__all__ = [
    "AES_GCM_AAD",
    "CryptoError",
    "DecryptionError",
    "EncodingError",
    "GCM_KEY_LEN",
    "GCM_MIN_WIRE_LEN",
    "GCM_NONCE_LEN",
    "GCM_TAG_LEN",
    "KeyConfigError",
    "constant_time_compare",
    "decrypt_aes_gcm",
    "encrypt_aes_gcm",
    "generate_aes256_key",
    "load_hex_key",
    "lock_pages",
    "random_bytes",
    "random_hex",
    "sha256",
    "sha256_hex",
    "urlsafe_b64decode",
    "urlsafe_b64encode",
    "validate_aes_key",
    "zeroize",
]

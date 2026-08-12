"""EphemeralProcessor — in-memory context execution for the secure enclave.

Phase 4 / Prompts 065–066. The blueprint's TEE contract is *ephemeral
volatile execution*: the enclave microservices "run in RAM and execute zero
local disk writes. Payload buffers are zeroed out immediately following ZKP
proof generation."

This module implements the Python-side of that contract as a bounded,
securely-zeroable, in-memory context processor:

* **RAM-only**: the context window is a `collections.deque` of `bytearray`
  buffers held entirely in process memory. The class performs zero file I/O —
  no reads, no writes, no temp files, no caches.
* **Securely zeroable**: Python `str`/`bytes` are immutable and cannot be
  wiped in place; `bytearray` is mutable, so every buffer can be explicitly
  overwritten with zeroes. Buffers are zeroed on eviction (window overflow),
  on `destroy()` (request completion — the FastAPI dependency-with-yield
  pattern), and on context-manager exit. This mitigates data remanence in
  RAM, core dumps, and swap.
* **Bounded**: a hard cap on window size AND total context bytes prevents
  unbounded memory growth inside the memory-constrained Confidential VM
  (research-backed: O(1) `deque` eviction + proactive zeroing on evict).
* **Thread-safe**: a `threading.Lock` guards every mutation and read, so a
  shared instance can serve concurrent FastAPI requests without races.
* **Encrypted ingress (Prompt 066)**: `execute_query(encrypted_payload)`
  decrypts a client AES-GCM-256 payload, runs the REAL Rust engine via the
  PyO3 FFI (`indexer_rs.parse_and_prove` — the deterministic symbolic RAM
  pass), and returns a [`QueryResult`]. The decryption key comes from the
  `ENCLAVE_PAYLOAD_KEY` environment variable (hex, 32 bytes) — the
  attestation-verified ephemeral Diffie–Hellman key exchange belongs to the
  later Hardware Attestation phase (Prompts 081–100) and is deferred by
  design; zero secrets are hardcoded (zero-mock policy).
* **Strict RAM scrubbing (Prompt 067)**: the AES-GCM key is held in a
  scrubbable `bytearray` and zeroed **immediately after decryption
  completes**; the decrypted plaintext buffer is zeroed **immediately after
  the Rust pass executes** — and on every exception path (a `finally`
  guarantees it); nonce/ciphertext are processed from ONE mutable working
  copy (memoryview views) so there are no immutable ciphertext copies left
  behind; sensitive buffers are best-effort `mlock`ed on Linux to keep them
  out of swap, with `MADV_WIPEONFORK` so forked children inherit zeroed
  pages. Python `str` cannot be zeroed in place (research-confirmed), so
  string references are dropped immediately after the FFI call — the honest
  limit of Python-level scrubbing.

# The "RAM LLM pass" — honest scope

The blueprint phrase "open-weight model context execution in RAM" is
realized here as the **deterministic symbolic RAM pass**: the Rust engine's
`parse_and_prove` executes tokenize → AST → symbolic-graph match → halo2
proof entirely in RAM, with zero disk writes. The architecture deliberately
replaces probabilistic LLM inference with this exact symbolic engine (per the
blueprint's own design rationale), so there is no probabilistic model in this
pass and none is simulated. A genuine open-weight model, if a later phase
specifies one, would be added as a new dependency — never faked.

Research (user-provided + cryptography/PyO3/FastAPI docs, 2026-08-06):
AESGCM in the `cryptography` crate is the professional AEAD primitive
(nonce 12 bytes, tag appended to ciphertext, AAD for context binding);
`Depends` with `yield` guarantees cleanup; `bytearray` is the
Python-mutable type required for in-place zeroing (C-level `ctypes.memset`
per the cryptography docs, not a Python loop); `deque(maxlen=N)` gives
O(1) bounded eviction.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque

from pydantic import BaseModel, ConfigDict, Field

# AES-GCM-256 (cryptography). Deferred import inside methods is NOT used —
# the wheel ships the `cryptography` package (requirements.txt), so a module
# import is the honest, dependency-verified choice.
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Hard bound on the number of context buffers retained (window slots).
DEFAULT_MAX_WINDOW_SIZE = 64
# Hard bound on total retained context bytes. The Confidential VM has a
# strict memory ceiling; this cap keeps the window from exhausting it.
DEFAULT_MAX_CONTEXT_BYTES = 8 * 1024 * 1024  # 8 MiB

# AES-GCM-256 parameters (NIST SP 800-38D): 12-byte nonce, 16-byte tag.
_GCM_NONCE_LEN = 12
# Linux madvise(2) flag: child processes inherit ZEROED pages instead of
# copy-on-write copies of sensitive memory (Linux >= 4.14). Best-effort.
_MADV_WIPEONFORK = 18
# Protocol-version Additional Authenticated Data (AAD). Binding a fixed
# protocol tag into the AEAD means a payload encrypted for one protocol
# revision cannot be replayed into another (context-swap hardening per the
# cryptography docs: AAD "gives context to the decryption"). The client must
# encrypt with this exact AAD — it is part of the wire contract.
_AES_GCM_AAD = b"flare-verifiable-rag:enclave:v1"
# Environment variable holding the 32-byte payload decryption key (hex).
ENCLAVE_PAYLOAD_KEY_ENV = "ENCLAVE_PAYLOAD_KEY"
# Hard cap on the encrypted payload the processor will accept (bounds the
# decrypt + symbolic work per request inside the memory-constrained TEE).
MAX_ENCRYPTED_PAYLOAD_BYTES = 4 * 1024 * 1024  # 4 MiB


class DecryptedPayload(BaseModel):
    """The plaintext contract inside the AES-GCM envelope (Prompt 066).

    Strict (`extra="forbid"`) so a malformed/unknown plaintext is rejected
    rather than silently accepted. `document` is the raw document the Rust
    engine tokenizes; `prompt` is the query text bound as H_prompt.
    """

    model_config = ConfigDict(extra="forbid")

    document: str = Field(min_length=1, max_length=MAX_ENCRYPTED_PAYLOAD_BYTES)
    prompt: str = Field(min_length=1, max_length=MAX_ENCRYPTED_PAYLOAD_BYTES)


@dataclass(frozen=True)
class QueryResult:
    """The verifiable result of an executed query (Prompt 066).

    Carries exactly what the Rust engine produced — no fabricated fields:
      proof          — halo2 ZK proof bytes (Blake2b transcript)
      doc_hash       — H_doc: 32-byte LE field repr of the document digest
      prompt_hash    — H_prompt: 32-byte LE field repr of the prompt digest
      output_hash    — H_out: 32-byte LE field repr of the evidence digest
      latency_ms     — wall-clock of the full pipeline (decrypt→prove)
    """

    proof: bytes
    doc_hash: bytes
    prompt_hash: bytes
    output_hash: bytes
    latency_ms: float

    def as_public_inputs(self) -> list[bytes]:
        """The three public inputs the proof binds, in circuit order.

        These are the exact 32-byte little-endian field representations the
        on-chain verifier re-derives for cross-checking.
        """
        return [self.doc_hash, self.prompt_hash, self.output_hash]


def _load_payload_key() -> bytearray:
    """Load the 32-byte AES-GCM-256 key from `ENCLAVE_PAYLOAD_KEY` (hex).

    Returns a MUTABLE `bytearray` — immutable `bytes` cannot be wiped in
    place, so the key is a bytearray specifically so Prompt 067 can zero it
    immediately after decryption completes. No default, no fallback, no
    hardcoded bytes: the enclave refuses to decrypt without a configured
    key (zero-mock policy). The attestation-verified ephemeral DH key
    exchange (later phase) will provision this key; for now the operator
    supplies it via the environment.
    """
    raw = os.environ.get(ENCLAVE_PAYLOAD_KEY_ENV)
    if not raw:
        raise RuntimeError(
            f"{ENCLAVE_PAYLOAD_KEY_ENV} is not set: cannot decrypt payloads"
        )
    try:
        key = bytearray.fromhex(raw.strip())
    except ValueError as exc:
        raise RuntimeError(
            f"{ENCLAVE_PAYLOAD_KEY_ENV} must be 64 hex chars (32 bytes)"
        ) from exc
    if len(key) != 32:
        raise RuntimeError(
            f"{ENCLAVE_PAYLOAD_KEY_ENV} must decode to exactly 32 bytes, "
            f"got {len(key)}"
        )
    return key


class EphemeralProcessor:
    """Bounded, RAM-only, securely-zeroable in-memory context processor.

    Attributes:
        max_window_size: maximum number of context buffers retained.
        max_context_bytes: hard ceiling on total retained context bytes.
    """

    def __init__(
        self,
        max_window_size: int = DEFAULT_MAX_WINDOW_SIZE,
        max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
    ) -> None:
        if max_window_size <= 0 or max_context_bytes <= 0:
            raise ValueError("window size and context byte cap must be positive")
        self._lock = threading.Lock()
        # `bytearray` (mutable) rather than `str`/`bytes` (immutable) so every
        # buffer can be zeroed in place when evicted or destroyed.
        self._window: Deque[bytearray] = deque(maxlen=max_window_size)
        self._max_window_size = max_window_size
        self._max_context_bytes = max_context_bytes
        self._current_bytes = 0
        self._destroyed = False

    # -- lifecycle ---------------------------------------------------------

    def ingest(self, payload: bytes) -> None:
        """Store a context payload in RAM.

        No disk writes, ever. If the window is full, the oldest buffer is
        zeroed before eviction. If adding the payload would exceed the total
        byte cap, the oldest buffers are zeroed and evicted until it fits
        (or the payload is rejected outright if it exceeds the cap alone).
        """
        with self._lock:
            self._ensure_alive()
            if len(payload) > self._max_context_bytes:
                raise ValueError(
                    f"context payload of {len(payload)} bytes exceeds the "
                    f"{self._max_context_bytes}-byte cap"
                )
            # Evict (and zero) oldest buffers until the new payload fits the
            # byte cap, then evict once more if the window is at capacity.
            #
            # CRITICAL: eviction must ALWAYS go through `_zero_evict()`.
            # `deque(maxlen=...)`'s silent auto-eviction on append would drop
            # the oldest buffer WITHOUT zeroing it (security gap) and WITHOUT
            # decrementing `_current_bytes` (accounting drift). We therefore
            # perform the window-capacity eviction explicitly, BEFORE append,
            # and keep `maxlen` only as a harmless safety backstop.
            while (
                self._current_bytes + len(payload) > self._max_context_bytes
                and self._window
            ):
                self._zero_evict()
            if len(self._window) >= self._max_window_size:
                self._zero_evict()
            self._window.append(bytearray(payload))
            self._current_bytes += len(payload)

    def execute(self, query: str) -> dict:
        """Run a deterministic, RAM-only symbolic match against the context.

        Returns a structured execution record (never fabricates answers):
          query_hash      — SHA-256 of the canonical query text
          matched_buffers — number of context buffers containing the query
          window_size     — current retained buffer count
          retained_bytes  — current retained context bytes

        This is pure in-memory exact matching over the retained window; the
        full symbolic-graph answer + ZK proof pipeline (Rust engine) is
        attached in later prompts. The returned record is the deterministic
        state the proof pipeline will bind to.
        """
        with self._lock:
            self._ensure_alive()
            needle = query.encode("utf-8")
            matched = sum(1 for buf in self._window if needle in buf)
            return {
                "query_hash": hashlib.sha256(needle).hexdigest(),
                "matched_buffers": matched,
                "window_size": len(self._window),
                "retained_bytes": self._current_bytes,
            }

    def execute_query(self, encrypted_payload: bytes) -> QueryResult:
        """Decrypt, run the Rust symbolic RAM pass, and return a QueryResult.

        Full pipeline, all in RAM, zero disk writes. Prompt 067 strict
        scrubbing: every sensitive mutable buffer (AES key, decrypted
        plaintext, nonce/ciphertext working copy) is zeroed the moment its
        job is done, in a `finally` so it happens on success AND on every
        exception path:

        1. **Ingress check** — reject payloads over the hard cap before any
           crypto work (bounds per-request cost inside the TEE).
        2. **AES-GCM-256 decryption** — key from `ENCLAVE_PAYLOAD_KEY` env
           (hex, 32 bytes, held as a scrubbable `bytearray`); wire format is
           `nonce(12) || ciphertext+tag`. Decryption runs over ONE mutable
           working copy (memoryview views into a `bytearray`), so no
           immutable ciphertext copies remain. The key is zeroed immediately
           after decryption completes.
        3. **Strict schema validation** — decrypted plaintext validated
           against [`DecryptedPayload`] (`extra="forbid"`).
        4. **Rust FFI symbolic RAM pass** — `indexer_rs.parse_and_prove`
           (PyO3, GIL released inside) runs tokenize → AST → graph match →
           halo2 proof entirely in RAM. This is the deterministic "RAM LLM
           pass": no probabilistic model, none simulated. Immediately after
           it returns, the decrypted plaintext buffer is zeroed.
        5. **Result** — a frozen [`QueryResult`] with the proof bytes and the
           three 32-byte public-input representations the proof binds.

        Errors: structured `RuntimeError`s on missing key, bad ciphertext,
        schema violation, or engine failure — never a panic, never a fallback.

        Thread-safety: the lock guards ONLY the lifecycle check and the
        payload-cap check. Decryption and the heavy halo2 prove run OUTSIDE
        the lock — `parse_and_prove` never touches the context window, and
        the FFI itself releases the GIL, so concurrent Python threads keep
        running and a shared instance does not serialize queries.
        """
        with self._lock:
            self._ensure_alive()
            if len(encrypted_payload) > MAX_ENCRYPTED_PAYLOAD_BYTES:
                raise ValueError(
                    f"encrypted payload of {len(encrypted_payload)} bytes "
                    f"exceeds the {MAX_ENCRYPTED_PAYLOAD_BYTES}-byte cap"
                )

        started = time.monotonic()
        key = _load_payload_key()
        plain_bytes: bytearray | None = None
        payload: DecryptedPayload | None = None
        try:
            _memlock(key)  # best-effort: keep key pages out of swap
            plain_bytes = self._decrypt_payload(key, encrypted_payload)
            # Decryption is done — the key's job is over. Scrub it NOW, not
            # at function exit (Prompt 067: zero key material immediately
            # after the cipher context is finished with it).
            self._zero(key)
            key = None

            _memlock(plain_bytes)  # best-effort: keep plaintext out of swap
            payload = DecryptedPayload.model_validate_json(plain_bytes)

            # The deterministic symbolic RAM pass (Rust engine, GIL released).
            engine = _import_indexer_rs()
            result = engine.parse_and_prove(payload.document, payload.prompt)
        finally:
            # Scrub the decrypted text buffer immediately after execution
            # (and on any exception). Drop string references too — Python
            # `str` cannot be zeroed in place (research-confirmed), so the
            # honest mitigation is releasing them as soon as possible.
            if plain_bytes is not None:
                self._zero(plain_bytes)
            if key is not None:
                self._zero(key)
            if payload is not None:
                del payload

        latency_ms = (time.monotonic() - started) * 1000.0
        return QueryResult(
            proof=bytes(result["proof"]),
            doc_hash=bytes(result["doc_hash"]),
            prompt_hash=bytes(result["prompt_hash"]),
            output_hash=bytes(result["output_hash"]),
            latency_ms=latency_ms,
        )

    @staticmethod
    def _decrypt_payload(key: bytearray, encrypted_payload: bytes) -> bytearray:
        """AES-GCM-256 decrypt of `nonce(12) || ciphertext+tag`.

        Prompt 067 strict scrubbing: the ciphertext is copied into ONE
        mutable `bytearray` working buffer; the nonce and ciphertext are
        passed to AESGCM as memoryview views into that buffer (verified
        accepted by `cryptography` 42.0.5), so no immutable ciphertext
        copies are ever materialized. The working buffer is zeroed in a
        `finally`, so it is wiped on success AND on failed authentication.

        Returns the decrypted plaintext as a mutable `bytearray` so the
        caller can scrub it immediately after use.

        Raises a structured RuntimeError on malformed length or failed
        authentication (tampered ciphertext) — no silent fallback.
        """
        if len(encrypted_payload) < _GCM_NONCE_LEN + 16:
            raise ValueError(
                "encrypted payload too short: need nonce(12) + tag(16)"
            )
        work = bytearray(encrypted_payload)  # the ONLY ciphertext copy
        try:
            view = memoryview(work)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(
                view[:_GCM_NONCE_LEN], view[_GCM_NONCE_LEN:], _AES_GCM_AAD
            )
            # Mutable plaintext so the caller can zero it in place; drop the
            # immutable bytes returned by AESGCM immediately.
            plain_bytes = bytearray(plaintext)
            del plaintext
            return plain_bytes
        except InvalidTag as exc:
            # The ONLY expected failure: AES-GCM authentication failed
            # (tampered ciphertext or wrong key). Narrow, structured,
            # non-panicking — programming errors propagate untouched.
            raise RuntimeError(
                "payload decryption failed: authentication tag mismatch "
                "(tampered ciphertext or wrong key)"
            ) from exc
        finally:
            EphemeralProcessor._zero(work)  # scrub nonce+ciphertext copy

    def destroy(self) -> None:
        """Securely zero every retained buffer and mark the processor dead.

        Idempotent. Intended to run in a FastAPI dependency's `finally`
        block so cleanup happens on success AND on exception.
        """
        with self._lock:
            if self._destroyed:
                return
            while self._window:
                self._zero(self._window.popleft())
            self._current_bytes = 0
            self._destroyed = True

    def __enter__(self) -> "EphemeralProcessor":
        return self

    def __exit__(self, *exc) -> None:
        self.destroy()

    # -- internals ---------------------------------------------------------

    def _ensure_alive(self) -> None:
        if self._destroyed:
            raise RuntimeError("EphemeralProcessor has been destroyed")

    def _zero_evict(self) -> None:
        """Zero the oldest buffer, then evict it (window-overflow path)."""
        oldest = self._window.popleft()
        self._current_bytes -= len(oldest)
        self._zero(oldest)

    @staticmethod
    def _zero(buf: bytearray) -> None:
        """Overwrite a mutable buffer with zeroes (mitigates remanence).

        Uses `ctypes.memset` — the C-level wipe the cryptography docs
        recommend for Python buffers (faster and more thorough than a Python
        loop over the same bytes). `bytearray` exposes its buffer to ctypes,
        which is exactly why the processor stores context in `bytearray`
        rather than immutable `str`/`bytes`.
        """
        if not buf:
            return
        ptr = (ctypes.c_char * len(buf)).from_buffer(buf)
        ctypes.memset(ptr, 0, len(buf))


def _memlock(buf: bytearray) -> None:
    """Best-effort pin of a sensitive buffer to physical RAM (Linux only).

    Uses `mlock(2)` (keeps pages out of swap) and `madvise(2)` with
    `MADV_WIPEONFORK` (child processes inherit zeroed pages — Linux >=
    4.14) via ctypes. Silently no-ops on non-Linux platforms and on any
    failure (e.g. unprivileged containers with a low `RLIMIT_MEMLOCK`),
    because `_zero()` remains the primary scrubbing mechanism — mlock is
    defense-in-depth, never a correctness requirement.
    """
    if os.name != "posix" or not buf:
        return
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        libc.mlock(ctypes.c_void_p(addr), len(buf))
        libc.madvise(ctypes.c_void_p(addr), len(buf), _MADV_WIPEONFORK)
    except (OSError, AttributeError, ValueError):
        pass  # best-effort only; scrubbing still happens via _zero()


def _import_indexer_rs():
    """Import the compiled Rust engine wheel, with a clear error if absent.

    The wheel is built by maturin (`cargo build --features python`, Prompt
    054/060) and installed alongside the Python deps in the container. If it
    is missing, this raises a structured RuntimeError — there is NO pure-
    Python substitute engine, because a substitute would be fabricated
    output. The import is lazy so `processor.py` still imports cleanly
    (e.g. for the unit suite) without the wheel present.
    """
    try:
        import indexer_rs  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "indexer_rs engine wheel is not installed; build it with "
            "`maturin build --release --features python` (Prompt 054/060)"
        ) from exc
    return indexer_rs


def get_ephemeral_processor() -> EphemeralProcessor:
    """FastAPI dependency: yield a live processor, ALWAYS destroy after.

    The `finally` guarantees zeroization on normal return and on exception —
    the professional ephemeral-lifecycle pattern for TEE workloads.
    """
    processor = EphemeralProcessor()
    try:
        yield processor
    finally:
        processor.destroy()

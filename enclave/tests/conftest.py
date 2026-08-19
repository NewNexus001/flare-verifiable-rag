"""Shared fixtures + TEE invariants for the enclave unit suite (Prompt 073).

Every test in this directory inherits two guarantees:

1. **RAM-only execution** — the ``assert_no_disk_io`` autouse fixture patches
   ``builtins.open``/``os.open`` so ANY write-mode file open attempted during
   a test fails the suite immediately. The processor performs zero file I/O
   by design (blueprint TEE contract: "run in RAM and execute zero local
   disk writes"); these tests turn that into a mechanically enforced
   invariant.

2. **Real crypto** — payload envelopes are produced with real AES-GCM-256
   (pyca/cryptography) under a real 32-byte key injected through the
   ``ENCLAVE_PAYLOAD_KEY`` env var (``monkeypatch.setenv``, auto-cleaned).

The FFI boundary (the compiled ``indexer_rs`` PyO3 wheel) is isolated
per-test with a deterministic ``FakeEngine`` injected into ``sys.modules``
in ``test_processor.py`` — professional boundary isolation for unit tests.
The REAL wheel round-trip is covered by ``test_real_engine_round_trip``
(skipped when the wheel is absent) and by the integration harness
``.tools/066_verify.py``.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

# Make `src.rag_engine.processor` importable regardless of the directory the
# suite is launched from (defensive; pyproject.toml also sets pythonpath).
_ENCLAVE_DIR = Path(__file__).resolve().parents[1]
if str(_ENCLAVE_DIR) not in sys.path:
    sys.path.insert(0, str(_ENCLAVE_DIR))

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from _testdata import DOC, PROMPT, TEST_KEY_HEX
from src.rag_engine.processor import (
    EphemeralProcessor,
    ENCLAVE_PAYLOAD_KEY_ENV,
    _AES_GCM_AAD,
)


@pytest.fixture
def enclave_key(monkeypatch):
    """Inject the real 32-byte AES key via the env var the processor reads."""
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    return bytes.fromhex(TEST_KEY_HEX)


@pytest.fixture
def processor():
    """A live EphemeralProcessor; always destroyed (all buffers zeroed)."""
    p = EphemeralProcessor()
    yield p
    p.destroy()


@pytest.fixture
def valid_payload(enclave_key):
    """A REAL AES-GCM-256 envelope exactly as a conforming client sends it:
    ``nonce(12) || ciphertext+tag``, encrypted under the protocol-version
    AAD (the wire contract the enclave decrypts with)."""
    nonce = os.urandom(12)
    ct = AESGCM(enclave_key).encrypt(
        nonce,
        json.dumps({"document": DOC, "prompt": PROMPT}).encode(),
        _AES_GCM_AAD,
    )
    return nonce + ct


class FakeEngine:
    """Deterministic stand-in for the compiled ``indexer_rs`` PyO3 wheel.

    A TEST DOUBLE for FFI boundary isolation only — the real wheel is
    exercised by ``test_real_engine_round_trip`` and ``.tools/066_verify.py``.
    It mirrors the wheel's call shape ``parse_and_prove(document, prompt)``
    and derives the three hash fields with REAL SHA-256 (no fabricated
    values), so the wrapper's behavior is asserted honestly.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_next: Exception | None = None

    def parse_and_prove(self, document: str, prompt: str) -> dict:
        self.calls.append((document, prompt))
        if self.fail_next is not None:
            raise self.fail_next
        doc_hash = hashlib.sha256(document.encode("utf-8")).digest()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).digest()
        output_hash = hashlib.sha256(doc_hash + prompt_hash).digest()
        return {
            "proof": b"fake-proof-" + doc_hash[:8],
            "doc_hash": doc_hash,
            "prompt_hash": prompt_hash,
            "output_hash": output_hash,
        }


@pytest.fixture
def fake_engine():
    """Shared FFI test double (Prompt 087: reused by test_processor and
    test_attestation) — injected into ``sys.modules`` so the lazy ``import
    indexer_rs`` resolves to it; restored afterwards."""
    engine = FakeEngine()
    prev = sys.modules.get("indexer_rs")
    sys.modules["indexer_rs"] = engine
    yield engine
    if prev is not None:
        sys.modules["indexer_rs"] = prev
    else:
        sys.modules.pop("indexer_rs", None)


@pytest.fixture(autouse=True)
def assert_no_disk_io(monkeypatch):
    """RAM-only invariant: fail the test the instant any write-mode file open
    is attempted. Read-only opens are delegated to the real implementation."""

    def _mode_writes(mode: str) -> bool:
        return any(ch in mode for ch in "wa+x") or "+" in mode

    real_open = open

    def guarded_open(file, mode="r", *args, **kwargs):
        if _mode_writes(mode):
            pytest.fail(
                f"RAM-only violation: disk write attempted via open({file!r}, {mode!r})"
            )
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", guarded_open)

    real_os_open = os.open
    write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

    def guarded_os_open(path, flags, *args, **kwargs):
        if flags & write_flags:
            pytest.fail(
                f"RAM-only violation: disk write attempted via os.open({path!r})"
            )
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", guarded_os_open)

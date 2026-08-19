"""Prompt 073 — unit tests verifying in-memory query processing.

Covers the ``EphemeralProcessor`` contract at the unit level:

* **RAM-only processing** — the ``assert_no_disk_io`` autouse fixture (see
  conftest.py) makes any disk-write attempt fail the suite mechanically.
* **Real crypto** — every payload is a REAL AES-GCM-256 envelope under a
  REAL 32-byte key; authentication failures (tamper / wrong key / wrong
  AAD) must be rejected with a structured error.
* **FFI isolation** — the compiled ``indexer_rs`` PyO3 wheel is replaced
  per-test by a deterministic ``FakeEngine`` injected into ``sys.modules``
  (professional boundary isolation per the pytest/PyO3 docs; the REAL wheel
  round-trip is covered by ``test_real_engine_round_trip``, skipped when the
  wheel is absent, and by the integration harness ``.tools/066_verify.py``).
* **Memory scrubbing** — ``ctypes.memset`` is spied on: every wipe must
  write ZEROS, and the key + plaintext + ciphertext-working-copy are all
  wiped on the success path AND on the engine-failure path.
* **No stdout/stderr leakage** — ``capsys`` proves the processing path
  prints nothing (in a TEE, stdout is routed to the untrusted host OS).
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sys
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from _testdata import DOC, PROMPT, TEST_KEY_HEX

from src.rag_engine.processor import (
    DecryptedPayload,
    EphemeralProcessor,
    QueryResult,
    ENCLAVE_PAYLOAD_KEY_ENV,
    MAX_ENCRYPTED_PAYLOAD_BYTES,
    _AES_GCM_AAD,
    _import_indexer_rs,
    _load_payload_key,
    get_ephemeral_processor,
)

# The compiled Rust wheel, if installed (maturin build, Prompts 054/060).
# Imported at collection time so the RAM-only guard never intercepts it.
try:
    import indexer_rs as _real_indexer_rs  # noqa: F401  (realness check)
    HAVE_REAL_ENGINE = True
except ImportError:  # pragma: no cover - depends on the build environment
    HAVE_REAL_ENGINE = False


# FakeEngine + fake_engine fixture now live in conftest.py (shared with
# test_attestation.py for Prompt 087) — one FFI test double, reused.


@pytest.fixture
def memset_spy(monkeypatch):
    """Spy on ``ctypes.memset`` recording ``(value, size)`` of every call.

    The only ``ctypes.memset`` callers in the processing path are the
    processor's ``_zero`` wipes (cryptography/AESGCM runs at the C layer and
    never routes through the Python ``ctypes`` module), so the recorded
    calls are exactly the scrubbing events.
    """
    calls: list[tuple[int, int]] = []
    real_memset = ctypes.memset

    def spy(ptr, value, size):
        calls.append((value, size))
        return real_memset(ptr, value, size)

    monkeypatch.setattr(ctypes, "memset", spy)
    return calls


def _envelope(plaintext, key: bytes) -> bytes:
    """A real AES-GCM-256 envelope over str/bytes plaintext (wire format)."""
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, data, _AES_GCM_AAD)


# ---------------------------------------------------------------------------
# QueryResult contract
# ---------------------------------------------------------------------------


def test_query_result_is_frozen():
    r = QueryResult(b"p", b"a" * 32, b"b" * 32, b"c" * 32, 1.0)
    with pytest.raises(FrozenInstanceError):
        r.proof = b"x"


def test_query_result_as_public_inputs_ordered():
    r = QueryResult(b"p", b"a" * 32, b"b" * 32, b"c" * 32, 1.0)
    assert r.as_public_inputs() == [r.doc_hash, r.prompt_hash, r.output_hash]
    assert all(len(h) == 32 for h in r.as_public_inputs())


# ---------------------------------------------------------------------------
# execute_query: in-memory processing (FFI isolated)
# ---------------------------------------------------------------------------


def test_execute_query_returns_queryresult(fake_engine, processor, valid_payload):
    result = processor.execute_query(valid_payload)
    assert isinstance(result, QueryResult)
    assert isinstance(result.proof, bytes) and len(result.proof) > 0
    for h in (result.doc_hash, result.prompt_hash, result.output_hash):
        assert isinstance(h, bytes) and len(h) == 32
    assert result.latency_ms >= 0.0


def test_execute_query_forwards_decoded_plaintext_to_engine(
    fake_engine, processor, valid_payload
):
    processor.execute_query(valid_payload)
    assert fake_engine.calls == [(DOC, PROMPT)]


def test_execute_query_deterministic_hashes(fake_engine, processor, valid_payload):
    r1 = processor.execute_query(valid_payload)
    r2 = processor.execute_query(valid_payload)
    assert r1.doc_hash == r2.doc_hash
    assert r1.prompt_hash == r2.prompt_hash
    assert r1.output_hash == r2.output_hash


def test_execute_query_missing_key_rejected(
    fake_engine, processor, valid_payload, monkeypatch
):
    monkeypatch.delenv(ENCLAVE_PAYLOAD_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError, match=ENCLAVE_PAYLOAD_KEY_ENV):
        processor.execute_query(valid_payload)


def test_execute_query_bad_key_hex_rejected(
    fake_engine, processor, valid_payload, monkeypatch
):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, "not-hex-at-all")
    with pytest.raises(RuntimeError, match="64 hex chars"):
        processor.execute_query(valid_payload)


def test_execute_query_short_key_rejected(
    fake_engine, processor, valid_payload, monkeypatch
):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, "0011")  # 1 byte
    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        processor.execute_query(valid_payload)


def test_execute_query_tampered_ciphertext_rejected(
    fake_engine, processor, valid_payload
):
    tampered = bytearray(valid_payload)
    tampered[-1] ^= 0x01
    with pytest.raises(RuntimeError, match="authentication tag mismatch"):
        processor.execute_query(bytes(tampered))


def test_execute_query_wrong_aad_rejected(
    fake_engine, processor, valid_payload, enclave_key
):
    nonce = os.urandom(12)
    wrong = nonce + AESGCM(enclave_key).encrypt(
        nonce,
        json.dumps({"document": DOC, "prompt": PROMPT}).encode(),
        b"flare-verifiable-rag:enclave:v2",  # wrong protocol revision
    )
    with pytest.raises(RuntimeError, match="authentication tag mismatch"):
        processor.execute_query(wrong)


def test_execute_query_wrong_key_rejected(
    fake_engine, processor, valid_payload, monkeypatch
):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, "99" * 32)
    with pytest.raises(RuntimeError, match="authentication tag mismatch"):
        processor.execute_query(valid_payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"",  # shorter than nonce(12) + tag(16)
        b"\x00" * 27,  # still too short
        b"\x00" * (MAX_ENCRYPTED_PAYLOAD_BYTES + 1),  # over the hard cap
    ],
    ids=["empty", "too-short", "over-cap"],
)
def test_execute_query_rejects_invalid_sizes(
    fake_engine, processor, enclave_key, payload
):
    with pytest.raises(ValueError):
        processor.execute_query(payload)


@pytest.mark.parametrize(
    "plaintext",
    [
        json.dumps({"document": DOC}),  # missing prompt
        json.dumps({"prompt": PROMPT}),  # missing document
        json.dumps({"document": DOC, "prompt": PROMPT, "extra": 1}),  # extra
        json.dumps({"document": 42, "prompt": PROMPT}),  # non-string field
        json.dumps({"document": "", "prompt": PROMPT}),  # empty document
        b"not-json-at-all",  # invalid JSON
    ],
    ids=["missing-prompt", "missing-document", "extra-field",
         "non-string-field", "empty-document", "invalid-json"],
)
def test_execute_query_rejects_invalid_plaintext_schema(
    fake_engine, processor, enclave_key, plaintext
):
    with pytest.raises(ValidationError):
        processor.execute_query(_envelope(plaintext, enclave_key))


def test_execute_query_zeroes_all_sensitive_buffers(
    fake_engine, processor, valid_payload, memset_spy
):
    processor.execute_query(valid_payload)
    zero_wipes = [size for value, size in memset_spy if value == 0]
    # key + decrypted plaintext + nonce/ciphertext working copy
    assert len(zero_wipes) >= 3, f"expected >=3 zero wipes, got {memset_spy}"
    assert all(value == 0 for value, _ in memset_spy)


def test_execute_query_zeroes_on_engine_failure(
    fake_engine, processor, valid_payload, memset_spy
):
    fake_engine.fail_next = RuntimeError("engine boom")
    with pytest.raises(RuntimeError, match="engine boom"):
        processor.execute_query(valid_payload)
    zero_wipes = [size for value, size in memset_spy if value == 0]
    assert len(zero_wipes) >= 3, f"expected >=3 zero wipes, got {memset_spy}"


def test_execute_query_no_stdout_stderr_leakage(
    fake_engine, processor, valid_payload, capsys
):
    processor.execute_query(valid_payload)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_ram_only_guard_fires_on_write_open():
    """Trust-but-verify: the autouse RAM-only guard itself must trip on a
    write-mode open — proving the invariant is actually enforced (and that
    a broken guard fails the suite instead of silently passing)."""
    with pytest.raises(pytest.fail.Exception, match="RAM-only violation"):
        with open("ram-only-guard-probe.txt", "w"):
            pass


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------


def test_load_payload_key_returns_scrubbable_bytearray(monkeypatch):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    key = _load_payload_key()
    assert isinstance(key, bytearray)
    assert len(key) == 32
    assert bytes(key) == bytes.fromhex(TEST_KEY_HEX)


def test_load_payload_key_requires_env(monkeypatch):
    monkeypatch.delenv(ENCLAVE_PAYLOAD_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError, match=ENCLAVE_PAYLOAD_KEY_ENV):
        _load_payload_key()


# ---------------------------------------------------------------------------
# FFI boundary
# ---------------------------------------------------------------------------


def test_import_indexer_rs_resolves_to_injected_boundary(fake_engine):
    assert _import_indexer_rs() is fake_engine


def test_missing_wheel_yields_structured_error(processor, valid_payload, enclave_key):
    prev = sys.modules.get("indexer_rs")
    sys.modules["indexer_rs"] = None  # `import indexer_rs` -> ImportError
    try:
        with pytest.raises(RuntimeError, match="not installed"):
            processor.execute_query(valid_payload)
    finally:
        if prev is not None:
            sys.modules["indexer_rs"] = prev
        else:
            sys.modules.pop("indexer_rs", None)


@pytest.mark.skipif(
    not HAVE_REAL_ENGINE, reason="indexer_rs wheel not installed in this env"
)
def test_real_engine_round_trip(processor, valid_payload):
    """The REAL compiled Rust wheel through the full in-memory pipeline."""
    result = processor.execute_query(valid_payload)
    assert isinstance(result, QueryResult)
    assert len(result.proof) > 0
    assert all(len(h) == 32 for h in result.as_public_inputs())


# ---------------------------------------------------------------------------
# In-memory context window (ingest / execute)
# ---------------------------------------------------------------------------


def test_ingest_stores_context_in_ram(processor):
    processor.ingest(b"alpha")
    processor.ingest(b"beta")
    rec = processor.execute("alpha")
    assert rec["matched_buffers"] == 1
    assert rec["window_size"] == 2
    assert rec["retained_bytes"] == 9  # len(b"alpha") + len(b"beta") = 5 + 4
    assert rec["query_hash"] == hashlib.sha256(b"alpha").hexdigest()


def test_ingest_zeroes_oldest_on_window_overflow():
    p = EphemeralProcessor(max_window_size=2)
    p.ingest(b"first")
    p.ingest(b"second")
    oldest = p._window[0]  # reference captured before eviction
    p.ingest(b"third")  # window full -> oldest zeroed + evicted
    assert oldest == bytearray(5)  # wiped in place, length preserved
    assert p.execute("first")["matched_buffers"] == 0
    assert p.execute("third")["matched_buffers"] == 1
    p.destroy()


def test_ingest_rejects_oversized_context(processor):
    with pytest.raises(ValueError, match="cap"):
        processor.ingest(b"x" * (processor._max_context_bytes + 1))


def test_ingest_evicts_until_byte_cap_fits():
    p = EphemeralProcessor(max_window_size=64, max_context_bytes=10)
    p.ingest(b"12345")
    p.ingest(b"67890")
    p.ingest(b"abc")  # 10+3 > 10 -> oldest zeroed + evicted
    assert p.execute("12345")["matched_buffers"] == 0
    assert p.execute("67890")["matched_buffers"] == 1
    assert p.execute("abc")["matched_buffers"] == 1
    p.destroy()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_destroy_zeroes_all_and_marks_dead():
    p = EphemeralProcessor(max_window_size=4)
    p.ingest(b"a")
    p.ingest(b"b")
    buffers = list(p._window)
    p.destroy()
    assert all(buf == bytearray(len(buf)) for buf in buffers)
    with pytest.raises(RuntimeError, match="destroyed"):
        p.ingest(b"c")
    with pytest.raises(RuntimeError, match="destroyed"):
        p.execute("a")
    assert p.destroy() is None  # idempotent


def test_context_manager_destroys_on_exit():
    with EphemeralProcessor() as p:
        p.ingest(b"x")
    with pytest.raises(RuntimeError, match="destroyed"):
        p.ingest(b"y")


@pytest.mark.parametrize(
    "window,cap", [(0, 1024), (4, 0), (-1, 1024)]
)
def test_constructor_rejects_nonpositive_bounds(window, cap):
    with pytest.raises(ValueError):
        EphemeralProcessor(max_window_size=window, max_context_bytes=cap)


def test_get_ephemeral_processor_dependency_destroys_after():
    gen = get_ephemeral_processor()
    p = next(gen)
    assert isinstance(p, EphemeralProcessor)
    p.ingest(b"x")
    gen.close()  # GeneratorExit -> the finally -> destroy()
    with pytest.raises(RuntimeError, match="destroyed"):
        p.ingest(b"y")


# ---------------------------------------------------------------------------
# Payload schema
# ---------------------------------------------------------------------------


def test_decrypted_payload_extra_forbid():
    with pytest.raises(ValidationError):
        DecryptedPayload.model_validate({"document": "d", "prompt": "p", "extra": 1})

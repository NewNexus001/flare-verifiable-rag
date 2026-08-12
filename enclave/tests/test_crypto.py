"""Prompt 074 — unit tests for AES-GCM-256 roundtrip encryption/decryption.

Targets the `src.crypto` package (Prompt 071): ``encrypt_aes_gcm`` /
``decrypt_aes_gcm`` over the standard ``nonce(12) || ciphertext || tag(16)``
wire format, plus the key/zeroize/compare helpers that make the roundtrip a
secure TEE contract.

What is proven, and how:

* **Known-answer test (KAT)** — the classic AES-256-GCM spec vector is pinned
  with EXPECTED values that were NOT taken from memory: they were verified
  live, byte-for-byte, across THREE independent implementations on this
  machine (2026-08-07): pyca/cryptography (OpenSSL), Node v26 crypto
  (OpenSSL), and pycryptodome (independent non-OpenSSL C code) — scripts in
  ``.tools/071_kat_*.py``, results documented in ``.tools/071_verify.py``.
  CT = ``522dc1f0...9f662``, TAG = ``76fc6ece0f4e1768cddf8853bb2d551b``.
  The package's decrypt path and the raw primitive must BOTH reproduce it.
* **Roundtrip matrix** — cartesian product of plaintext sizes (empty, 1 byte,
  text, 1 KiB, >64 KiB, 256 KiB binary, bytearray/memoryview inputs) x AAD
  variants (protocol AAD, empty, short custom, 1 KiB) — the professional
  edge-case grid from the cryptography.io AEAD docs.
* **AAD binding** — a ciphertext under one AAD is mathematically useless
  under another (context-swap hardening).
* **Tamper-evidence** — flipped nonce/ciphertext/tag bytes, wrong key, and
  garbage all raise the typed :class:`DecryptionError` (never a panic).
* **Wire format** — ``len(envelope) == 12 + len(pt) + 16``, manual split
  decrypts via the raw primitive, nonces are fresh on every encrypt.
* **Strict key validation** — exactly 32 bytes; bytes/bytearray/memoryview
  accepted; str/int/short/long rejected with :class:`KeyConfigError`.
* **Scrubbing** — decrypted plaintext is a mutable ``bytearray`` that
  ``zeroize`` wipes in place; immutable input is refused.
* **Property-based** — hypothesis roundtrip invariants over arbitrary binary
  (the standard practice in crypto libraries per the research), with the
  example database disabled so the RAM-only guard (conftest) is never
  tripped by hypothesis bookkeeping.
* **No TEE leakage** — capsys proves zero stdout/stderr (in a TEE, stdout
  is routed to the untrusted host OS).

The ``assert_no_disk_io`` autouse fixture from conftest.py applies here too:
any write-mode file open during a crypto test fails the suite.
"""

from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hypothesis import given, settings
from hypothesis import strategies as st

# Hypothesis lazily imports some internal modules on the FIRST @given run.
# pytest's assertion-rewrite hook writes their .pyc cache at that moment;
# importing them here at COLLECTION time (before any autouse fixture is
# active) keeps the RAM-only guard from tripping on infrastructure
# bookkeeping during the test run.
from hypothesis.internal.conjecture import engine as _h_engine  # noqa: E402,F401
from hypothesis.internal.conjecture import optimiser as _h_optimiser  # noqa: E402,F401

from _testdata import TEST_KEY_HEX

from src.crypto import (
    AES_GCM_AAD,
    CryptoError,
    DecryptionError,
    EncodingError,
    GCM_NONCE_LEN,
    GCM_TAG_LEN,
    KeyConfigError,
    constant_time_compare,
    decrypt_aes_gcm,
    encrypt_aes_gcm,
    generate_aes256_key,
    load_hex_key,
    random_bytes,
    random_hex,
    sha256,
    sha256_hex,
    urlsafe_b64decode,
    urlsafe_b64encode,
    validate_aes_key,
    zeroize,
)

@pytest.fixture
def key():
    """A fresh real AES-256 key per test (cryptography's generator)."""
    return generate_aes256_key()


# ---------------------------------------------------------------------------
# Known-answer test (3-implementation cross-verified, NOT from memory)
# ---------------------------------------------------------------------------

# Classic AES-256-GCM specification vector. Expected CT/TAG below were
# verified byte-identical across pyca/cryptography, Node v26 (OpenSSL) and
# pycryptodome on 2026-08-07 (.tools/071_kat_*.py) — see .tools/071_verify.py.
KAT_KEY = bytes.fromhex(
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
)
KAT_IV = bytes.fromhex("cafebabefacedbaddecaf888")
KAT_PT = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
KAT_AAD = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
KAT_CT = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
)
KAT_TAG = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")


def test_kat_primitive_matches():
    """The raw primitive reproduces the cross-verified vector exactly."""
    out = AESGCM(KAT_KEY).encrypt(KAT_IV, KAT_PT, KAT_AAD)
    assert out[: len(KAT_PT)] == KAT_CT
    assert out[len(KAT_PT) :] == KAT_TAG


def test_kat_decrypt_through_package():
    """Our wrapper's decrypt path accepts the standard nonce||ct||tag
    envelope and recovers the exact plaintext (wire format proven)."""
    envelope = KAT_IV + KAT_CT + KAT_TAG
    assert decrypt_aes_gcm(KAT_KEY, envelope, KAT_AAD) == bytearray(KAT_PT)


def test_kat_encrypt_through_primitive():
    """Our wrapper's encrypt output decrypts under the raw primitive — i.e.
    the envelope is standard-compliant AES-GCM, not a private format."""
    envelope = encrypt_aes_gcm(KAT_KEY, KAT_PT, KAT_AAD)
    assert AESGCM(KAT_KEY).decrypt(envelope[:12], envelope[12:], KAT_AAD) == KAT_PT


# ---------------------------------------------------------------------------
# Roundtrip matrix: plaintext sizes x AAD variants
# ---------------------------------------------------------------------------

PLAINTEXTS = [
    b"",  # empty: critical edge case
    b"A",  # 1 byte
    b"hello secure enclave",  # short text
    b"A" * 1024,  # 1 KiB
    b"A" * (64 * 1024 + 1),  # just past the 64 KiB boundary
    bytes(range(256)) * 1024,  # 256 KiB, every byte value
    bytearray(b"mutable buffer input"),  # bytearray input
    memoryview(b"memoryview input"),  # memoryview input
]
AADS = [
    AES_GCM_AAD,  # protocol-version AAD (the wire contract default)
    b"",  # empty AAD
    b"v1.0|/api/rag|sess_abc|seq_004",  # short context-bound AAD
    b"A" * 1024,  # long AAD
]


@pytest.mark.parametrize(
    "plaintext", PLAINTEXTS,
    ids=["empty", "1-byte", "short-text", "1kib", "64kib+1",
         "256kib-binary", "bytearray", "memoryview"],
)
@pytest.mark.parametrize(
    "aad", AADS,
    ids=["protocol-aad", "empty-aad", "context-aad", "1kib-aad"],
)
def test_roundtrip_matrix(key, plaintext, aad):
    """Encrypt then decrypt recovers the exact original plaintext, and the
    result is a scrubbable bytearray (the TEE contract)."""
    envelope = encrypt_aes_gcm(key, plaintext, aad)
    decrypted = decrypt_aes_gcm(key, envelope, aad)
    assert isinstance(decrypted, bytearray), "decrypt must return mutable bytearray"
    assert decrypted == bytearray(plaintext)


# ---------------------------------------------------------------------------
# AAD binding (context-swap hardening)
# ---------------------------------------------------------------------------


def test_wrong_aad_rejected(key):
    env = encrypt_aes_gcm(key, b"data", b"tenant:acme")
    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt_aes_gcm(key, env, b"tenant:other")


def test_wrong_aad_one_byte_off(key):
    env = encrypt_aes_gcm(key, b"data", b"protocol-v1")
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, env, b"protocol-v2")


def test_empty_aad_binds_like_any_other(key):
    env = encrypt_aes_gcm(key, b"data", aad=b"")
    assert decrypt_aes_gcm(key, env, aad=b"") == bytearray(b"data")
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(key, env, aad=AES_GCM_AAD)


# ---------------------------------------------------------------------------
# Tamper-evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("position", ["nonce", "ciphertext", "tag"])
def test_tampered_envelope_rejected(key, position):
    pt = b"Confidential RAG query payload"
    env = bytearray(encrypt_aes_gcm(key, pt))
    if position == "nonce":
        env[0] ^= 0x01
    elif position == "ciphertext":
        env[GCM_NONCE_LEN + len(pt) // 2] ^= 0x01
    else:
        env[-1] ^= 0x01
    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt_aes_gcm(key, bytes(env))


def test_wrong_key_rejected(key):
    env = encrypt_aes_gcm(key, b"data")
    other = generate_aes256_key()
    assert other != key
    with pytest.raises(DecryptionError):
        decrypt_aes_gcm(other, env)


@pytest.mark.parametrize(
    "payload",
    [b"", b"\x00" * 27, os.urandom(27)],
    ids=["empty", "27-zero-bytes", "27-random-bytes"],
)
def test_truncated_envelope_rejected(key, payload):
    with pytest.raises(DecryptionError, match="too short"):
        decrypt_aes_gcm(key, payload)


def test_garbage_envelope_rejected(key):
    """Right length, wrong content: auth failure, not a length error."""
    with pytest.raises(DecryptionError, match="authentication failed"):
        decrypt_aes_gcm(key, os.urandom(40))


# ---------------------------------------------------------------------------
# Wire format + nonce freshness
# ---------------------------------------------------------------------------


def test_wire_format_length(key):
    pt = b"Test 123"
    env = encrypt_aes_gcm(key, pt)
    assert len(env) == GCM_NONCE_LEN + len(pt) + GCM_TAG_LEN


def test_wire_format_manual_split(key):
    pt = b"wire format check"
    env = encrypt_aes_gcm(key, pt, aad=b"ctx")
    # nonce(12) prepended, ct+tag appended — recover pt with the raw primitive
    assert AESGCM(key).decrypt(env[:GCM_NONCE_LEN], env[GCM_NONCE_LEN:], b"ctx") == pt


def test_nonce_uniqueness(key):
    pt = b"same data"
    env1 = encrypt_aes_gcm(key, pt)
    env2 = encrypt_aes_gcm(key, pt)
    assert env1 != env2  # fresh CSPRNG nonce -> different ciphertext
    assert env1[:GCM_NONCE_LEN] != env2[:GCM_NONCE_LEN]


def test_many_nonces_unique(key):
    nonces = {encrypt_aes_gcm(key, b"x")[:GCM_NONCE_LEN] for _ in range(20)}
    assert len(nonces) == 20


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------


def test_validate_aes_key_accepts_bytes_like():
    raw = bytes(32)
    assert validate_aes_key(raw) == raw
    assert validate_aes_key(bytearray(raw)) == raw
    assert validate_aes_key(memoryview(raw)) == raw


@pytest.mark.parametrize(
    "bad_key",
    [b"", bytes(16), bytes(31), bytes(33), "A" * 32, 123456, None],
    ids=["empty", "16-byte", "31-byte", "33-byte", "str", "int", "None"],
)
def test_validate_aes_key_rejects(bad_key):
    with pytest.raises(KeyConfigError):
        validate_aes_key(bad_key)


def test_encrypt_rejects_bad_key():
    with pytest.raises(KeyConfigError):
        encrypt_aes_gcm(bytes(16), b"data")


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def test_generate_aes256_key_length():
    assert len(generate_aes256_key()) == 32


def test_generate_aes256_key_unique():
    assert generate_aes256_key() != generate_aes256_key()


# ---------------------------------------------------------------------------
# Scrubbing the decrypted plaintext
# ---------------------------------------------------------------------------


def test_decrypted_plaintext_scrubs_in_place(key):
    env = encrypt_aes_gcm(key, b"super-secret plaintext")
    plain = decrypt_aes_gcm(key, env)
    zeroize(plain)
    assert plain == bytearray(len(plain))


def test_zeroize_wipes_buffer():
    buf = bytearray(b"key-material")
    zeroize(buf)
    assert buf == bytearray(len(buf))


def test_zeroize_rejects_immutable():
    with pytest.raises(TypeError):
        zeroize(b"cannot wipe immutable bytes")


# ---------------------------------------------------------------------------
# Supporting helpers tied to the roundtrip contract
# ---------------------------------------------------------------------------


def test_sha256_fips_reference():
    fips_abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_hex(b"abc") == fips_abc
    assert sha256(b"abc") == bytes.fromhex(fips_abc)


def test_constant_time_compare_basics():
    assert constant_time_compare(b"abc", b"abc")
    assert not constant_time_compare(b"abc", b"abd")
    assert not constant_time_compare(b"abc", b"abcd")
    assert constant_time_compare("abc", b"abc")  # str/bytes normalized
    with pytest.raises(CryptoError):
        constant_time_compare(123, 456)


_LOAD_ENV = "074_TEST_KEY"


@pytest.mark.parametrize(
    "env_value,expected",
    [
        (TEST_KEY_HEX, bytes.fromhex(TEST_KEY_HEX)),
        ("0x" + TEST_KEY_HEX, bytes.fromhex(TEST_KEY_HEX)),
        (TEST_KEY_HEX.upper(), bytes.fromhex(TEST_KEY_HEX)),
    ],
    ids=["plain-hex", "0x-prefix", "uppercase"],
)
def test_load_hex_key_valid(monkeypatch, env_value, expected):
    monkeypatch.setenv(_LOAD_ENV, env_value)
    loaded = load_hex_key(_LOAD_ENV)
    assert isinstance(loaded, bytearray)  # scrubbable
    assert bytes(loaded) == expected


@pytest.mark.parametrize(
    "env_value", ["", "zznothex", "00" * 31, "00" * 33],
    ids=["empty", "bad-hex", "31-bytes", "33-bytes"],
)
def test_load_hex_key_invalid(monkeypatch, env_value):
    monkeypatch.setenv(_LOAD_ENV, env_value)
    with pytest.raises(KeyConfigError):
        load_hex_key(_LOAD_ENV)


def test_load_hex_key_missing_env(monkeypatch):
    monkeypatch.delenv(_LOAD_ENV, raising=False)
    with pytest.raises(KeyConfigError, match="not set"):
        load_hex_key(_LOAD_ENV)


def test_urlsafe_b64_roundtrip():
    raw = b"\xfb\xff\x00secret\x00\x01"
    wire = urlsafe_b64encode(raw)
    assert urlsafe_b64decode(wire) == raw
    with pytest.raises(EncodingError):
        urlsafe_b64decode("!!!not-base64!!!")


def test_random_helpers():
    assert len(random_bytes(32)) == 32
    assert len(random_hex(16)) == 32
    assert random_bytes(8) != random_bytes(8)


# ---------------------------------------------------------------------------
# Property-based roundtrip invariants
# ---------------------------------------------------------------------------


@settings(max_examples=100, database=None, deadline=None)
@given(plaintext=st.binary(max_size=4096), aad=st.binary(max_size=256))
def test_hypothesis_roundtrip_invariants(plaintext, aad):
    """Arbitrary binary input must always roundtrip (hypothesis fuzzing).
    The key is generated INSIDE the test (no function-scoped fixture) so
    hypothesis health checks stay clean."""
    key = generate_aes256_key()
    envelope = encrypt_aes_gcm(key, plaintext, aad)
    assert decrypt_aes_gcm(key, envelope, aad) == bytearray(plaintext)


# ---------------------------------------------------------------------------
# TEE: no stdout/stderr leakage
# ---------------------------------------------------------------------------


def test_crypto_no_stdout_stderr_leakage(key, capsys):
    env = encrypt_aes_gcm(key, b"quiet", b"aad")
    decrypt_aes_gcm(key, env, b"aad")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


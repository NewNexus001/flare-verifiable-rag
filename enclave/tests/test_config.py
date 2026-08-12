"""Prompt 076 — unit tests for ``src.config`` environment configuration.

Follows the research's point 7: env-config modules are tested by
manipulating the environment (``monkeypatch.setenv``/``delenv`` and explicit
``environ`` mappings) and by asserting that ZERO environment reads happen at
import time. Every test here is network-free and disk-free (the conftest
RAM-only guard applies), and each test runs against the REAL module with
REAL env-var names.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

import pytest

# Pre-import web3 at collection time so the lazy import inside the address
# validator never triggers a first-import bytecode-cache write mid-test
# (the conftest RAM-only guard turns such writes into failures).
import web3  # noqa: F401

from src import config
from src.config import (
    CONTRACT_REGISTRY_ADDR_ENV,
    COSTON2_RPC_URL_ENV,
    DEFAULT_CONTRACT_REGISTRY_ADDR,
    DEFAULT_COSTON2_RPC_URL,
    DEFAULT_LOG_LEVEL,
    ENCLAVE_ATTESTER_KEY_ENV,
    ENCLAVE_PAYLOAD_KEY_ENV,
    FLARE_CONTRACT_REGISTRY_ENV,
    InvalidLogLevelError,
    LOG_LEVEL_ENV,
    SecretMissingError,
    Settings,
    SettingsError,
    configure_logging,
    get_settings,
    reset_settings_cache,
)

from _testdata import TEST_KEY_HEX

# A real 32-byte secret (64 hex chars) for the zero-defaults tests.
_VALID_ENV = {
    ENCLAVE_PAYLOAD_KEY_ENV: TEST_KEY_HEX,
    ENCLAVE_ATTESTER_KEY_ENV: "0x" + TEST_KEY_HEX,
}


@pytest.fixture(autouse=True)
def _fresh_settings_cache():
    """No cross-test pollution from the process-wide lru_cache."""
    reset_settings_cache()
    yield
    reset_settings_cache()


# --- Pillar 1: zero reads at import time -----------------------------------


def test_import_never_reads_environment():
    """Importing config in a fresh subprocess (all env vars absent) must not
    raise, and must not materialize settings — the strongest proof that zero
    environment reads happen at import time. Runs out-of-process so the
    autouse cache-reset fixture cannot mask import-time behavior."""
    enclave_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (
            ENCLAVE_PAYLOAD_KEY_ENV,
            ENCLAVE_ATTESTER_KEY_ENV,
            COSTON2_RPC_URL_ENV,
            CONTRACT_REGISTRY_ADDR_ENV,
            FLARE_CONTRACT_REGISTRY_ENV,
            LOG_LEVEL_ENV,
        )
    }
    script = (
        "import sys; sys.path.insert(0, %r);\n"
        "from src import config;\n"
        "assert config.get_settings.cache_info().currsize == 0;\n"
        "print('IMPORT_OK')"
    ) % enclave_dir
    proc = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "IMPORT_OK" in proc.stdout


def test_from_env_reads_only_when_called(monkeypatch):
    """Values come from the environment AT CALL TIME, not import time."""
    monkeypatch.setenv(COSTON2_RPC_URL_ENV, "https://example.invalid/endpoint")
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, TEST_KEY_HEX)
    s = Settings.from_env()
    assert s.coston2_rpc_url == "https://example.invalid/endpoint"


# --- Pillar 3: documented defaults for non-secrets -------------------------


def test_public_defaults_with_valid_secrets():
    s = Settings.from_env(_VALID_ENV)
    assert s.coston2_rpc_url == DEFAULT_COSTON2_RPC_URL
    assert s.log_level == DEFAULT_LOG_LEVEL
    assert s.log_level_int == logging.INFO


def test_default_registry_address_is_checksummed():
    s = Settings.from_env(_VALID_ENV)
    assert s.contract_registry_addr.startswith("0x")
    assert len(s.contract_registry_addr) == 42
    # Canonical EIP-55 checksum of the documented bootstrap address.
    expected = web3.Web3.to_checksum_address(DEFAULT_CONTRACT_REGISTRY_ADDR.lower())
    assert s.contract_registry_addr == expected
    assert web3.Web3.is_checksum_address(s.contract_registry_addr)


def test_registry_lowercase_input_normalized_to_checksum():
    lower = "0x" + "ad67fe66660fb8dfe9d6b1b4240d8650e30f6019"
    s = Settings.from_env({**_VALID_ENV, CONTRACT_REGISTRY_ADDR_ENV: lower})
    assert s.contract_registry_addr != lower
    assert web3.Web3.is_checksum_address(s.contract_registry_addr)


# --- Pillar 2 + validators: overrides and strict validation ----------------


def test_env_overrides(monkeypatch):
    monkeypatch.setenv(COSTON2_RPC_URL_ENV, "wss://node.example/stream")
    monkeypatch.setenv(CONTRACT_REGISTRY_ADDR_ENV, "0x" + "11" * 20)
    monkeypatch.setenv(LOG_LEVEL_ENV, "debug")
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, TEST_KEY_HEX)
    s = get_settings()
    assert s.coston2_rpc_url == "wss://node.example/stream"
    assert s.contract_registry_addr == web3.Web3.to_checksum_address("0x" + "11" * 20)
    assert s.log_level == "DEBUG"
    assert s.log_level_int == logging.DEBUG


def test_legacy_registry_alias_supported():
    s = Settings.from_env(
        {**_VALID_ENV, FLARE_CONTRACT_REGISTRY_ENV: "0x" + "22" * 20}
    )
    assert s.contract_registry_addr == web3.Web3.to_checksum_address("0x" + "22" * 20)


def test_registry_new_var_preferred_over_alias():
    s = Settings.from_env(
        {
            **_VALID_ENV,
            CONTRACT_REGISTRY_ADDR_ENV: "0x" + "33" * 20,
            FLARE_CONTRACT_REGISTRY_ENV: "0x" + "44" * 20,
        }
    )
    assert s.contract_registry_addr == web3.Web3.to_checksum_address("0x" + "33" * 20)


@pytest.mark.parametrize(
    ("level", "expected_int"),
    [
        ("DEBUG", logging.DEBUG),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
        ("ERROR", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
    ],
)
def test_log_level_mapping(level, expected_int):
    s = Settings.from_env({**_VALID_ENV, LOG_LEVEL_ENV: level})
    assert s.log_level == level
    assert s.log_level_int == expected_int


def test_log_level_case_insensitive_and_stripped():
    s = Settings.from_env({**_VALID_ENV, LOG_LEVEL_ENV: "  warning "})
    assert s.log_level == "WARNING"
    assert s.log_level_int == logging.WARNING


@pytest.mark.parametrize("bad", ["VERBOSE", "TRACE", "INF0", "info x", "NOTSET2"])
def test_invalid_log_level_raises(bad):
    with pytest.raises(InvalidLogLevelError):
        Settings.from_env({**_VALID_ENV, LOG_LEVEL_ENV: bad})


@pytest.mark.parametrize("bad", ["ftp://flare.example/rpc", "coston2-api.flare.network", "//no-scheme", "https:/missing-slash"])
def test_invalid_rpc_url_raises(bad):
    with pytest.raises(SettingsError):
        Settings.from_env({**_VALID_ENV, COSTON2_RPC_URL_ENV: bad})


@pytest.mark.parametrize(
    "bad",
    [
        "0x123",  # too short
        "0x" + "12" * 21,  # 42 hex chars (too long)
        "0x" + "gg" * 20,  # non-hex
        "0x" + "12" * 19 + "xy",  # non-hex tail
        "12" * 20,  # missing 0x prefix
    ],
)
def test_invalid_evm_address_raises(bad):
    with pytest.raises(SettingsError):
        Settings.from_env({**_VALID_ENV, CONTRACT_REGISTRY_ADDR_ENV: bad})


# --- Pillar 2: zero-defaults for secrets ------------------------------------


def test_payload_key_missing_raises():
    env = {k: v for k, v in _VALID_ENV.items() if k != ENCLAVE_PAYLOAD_KEY_ENV}
    with pytest.raises(SecretMissingError) as exc:
        Settings.from_env(env)
    assert ENCLAVE_PAYLOAD_KEY_ENV in str(exc.value)


def test_attester_key_missing_raises():
    env = {k: v for k, v in _VALID_ENV.items() if k != ENCLAVE_ATTESTER_KEY_ENV}
    with pytest.raises(SecretMissingError) as exc:
        Settings.from_env(env)
    assert ENCLAVE_ATTESTER_KEY_ENV in str(exc.value)


@pytest.mark.parametrize(
    "bad",
    [
        "a" * 63,  # 63 hex chars
        "a" * 65,  # 65 hex chars
        "zz" * 32,  # non-hex
    ],
)
def test_payload_key_format_rejects(bad):
    with pytest.raises(SettingsError):
        Settings.from_env({**_VALID_ENV, ENCLAVE_PAYLOAD_KEY_ENV: bad})


def test_payload_key_whitespace_stripped():
    s = Settings.from_env(
        {**_VALID_ENV, ENCLAVE_PAYLOAD_KEY_ENV: TEST_KEY_HEX + "  "}
    )
    assert s.payload_key_hex == TEST_KEY_HEX.lower()


def test_payload_key_rejects_0x_prefix():
    # processor's loader uses bytearray.fromhex which does NOT accept 0x.
    with pytest.raises(SettingsError):
        Settings.from_env({**_VALID_ENV, ENCLAVE_PAYLOAD_KEY_ENV: "0x" + TEST_KEY_HEX})


def test_attester_key_accepts_with_and_without_0x():
    s = Settings.from_env(
        {**_VALID_ENV, ENCLAVE_ATTESTER_KEY_ENV: TEST_KEY_HEX}
    )
    assert s.attester_key_hex == TEST_KEY_HEX.lower()
    s2 = Settings.from_env(
        {**_VALID_ENV, ENCLAVE_ATTESTER_KEY_ENV: "0x" + TEST_KEY_HEX}
    )
    assert s2.attester_key_hex == TEST_KEY_HEX.lower()


def test_attester_key_bad_length_raises():
    with pytest.raises(SettingsError):
        Settings.from_env({**_VALID_ENV, ENCLAVE_ATTESTER_KEY_ENV: "b" * 63})


# --- Cache semantics --------------------------------------------------------


def test_get_settings_cached_and_resettable(monkeypatch):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, TEST_KEY_HEX)
    first = get_settings()
    second = get_settings()
    assert first is second
    monkeypatch.setenv(COSTON2_RPC_URL_ENV, "https://cache.example/endpoint")
    # Cache still serves the old snapshot until reset.
    assert get_settings().coston2_rpc_url == DEFAULT_COSTON2_RPC_URL
    reset_settings_cache()
    # Environment change is now visible.
    assert get_settings().coston2_rpc_url == "https://cache.example/endpoint"


def test_env_removal_returns_to_default(monkeypatch):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(LOG_LEVEL_ENV, "ERROR")
    reset_settings_cache()
    assert get_settings().log_level == "ERROR"
    monkeypatch.delenv(LOG_LEVEL_ENV)
    reset_settings_cache()
    assert get_settings().log_level == DEFAULT_LOG_LEVEL


# --- Pillar 5: secrets never leak -------------------------------------------


def test_public_snapshot_never_exposes_secrets():
    s = Settings.from_env(_VALID_ENV)
    snap = s.get_public_snapshot()
    assert set(snap.keys()) == {
        COSTON2_RPC_URL_ENV,
        CONTRACT_REGISTRY_ADDR_ENV,
        LOG_LEVEL_ENV,
    }
    joined = "|".join(snap.values())
    assert TEST_KEY_HEX.lower() not in joined
    assert ENCLAVE_PAYLOAD_KEY_ENV not in joined
    assert ENCLAVE_ATTESTER_KEY_ENV not in joined


def test_repr_redacts_secret_fields():
    s = Settings.from_env(_VALID_ENV)
    rendered = repr(s)
    assert TEST_KEY_HEX.lower() not in rendered
    assert s.attester_key_hex not in rendered
    assert ENCLAVE_PAYLOAD_KEY_ENV not in rendered


# --- configure_logging ------------------------------------------------------


def test_configure_logging_uses_validated_level(monkeypatch):
    captured = {}

    def fake_basic_config(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(logging, "basicConfig", fake_basic_config)
    s = Settings.from_env({**_VALID_ENV, LOG_LEVEL_ENV: "DEBUG"})
    configure_logging(s)
    assert captured.get("level") == logging.DEBUG
    assert "%(levelname)s" in captured.get("format", "")


def test_configure_logging_defaults_to_cached_settings(monkeypatch):
    monkeypatch.setenv(ENCLAVE_PAYLOAD_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, TEST_KEY_HEX)
    monkeypatch.setenv(LOG_LEVEL_ENV, "WARNING")
    reset_settings_cache()
    captured = {}

    def fake_basic_config(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(logging, "basicConfig", fake_basic_config)
    configure_logging()
    assert captured.get("level") == logging.WARNING

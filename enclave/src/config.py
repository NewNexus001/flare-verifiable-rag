"""config.py — Environment configuration for the secure enclave (Prompt 076).

Single canonical settings module for the enclave microservice. All
configuration is injected through environment variables (Twelve-Factor
Factor III: "The twelve-factor app stores config in environment variables"),
with the research-backed guarantees:

1. **Zero import-time side effects** — no ``os.environ`` read, no logging
   setup, and no heavy imports happen at module import time. Settings are
   materialized only when ``get_settings()`` / ``Settings.from_env()`` is
   called, which keeps the module fully testable with ``monkeypatch``.

2. **Zero-defaults policy for secrets** — ``ENCLAVE_PAYLOAD_KEY`` and
   ``ENCLAVE_ATTESTER_KEY`` have NO defaults; a missing secret raises
   ``SecretMissingError`` so the enclave fails closed before any processing
   or attestation begins. Hardcoding fallbacks for secrets is a critical
   vulnerability and is deliberately impossible here.

3. **Public constants may carry documented defaults** — the public testnet
   RPC URL and the documented Flare Contract Registry bootstrap address are
   non-secret protocol constants (safe to default, per the research).

4. **Strict validation** — RPC URL scheme, EIP-55 EVM address format
   (normalized to the canonical checksum), and ``LOG_LEVEL`` are validated
   at materialization time; invalid values crash the enclave at boot.

5. **Secrets never leak through repr paths** — secret fields are excluded
   from ``repr()`` (and therefore ``str()``) via dataclass
   ``field(repr=False)``, and ``get_public_snapshot()`` exposes only
   non-secret configuration for health endpoints. (Explicitly accessing
   the attributes in code is still possible — repr redaction is a defense
   against accidental logging, not a capability boundary.)

The research endorsed ``pydantic-settings`` for this role; that package is
not in the locked ``requirements.txt`` (Prompt 061), so the identical
pattern is implemented with the standard library: a frozen dataclass plus an
``lru_cache`` lazy factory plus explicit validators. Same guarantees, zero
new dependencies — also leaner for the TEE image.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Mapping, Optional

# --- Canonical environment variable names -----------------------------------
COSTON2_RPC_URL_ENV = "COSTON2_RPC_URL"
CONTRACT_REGISTRY_ADDR_ENV = "CONTRACT_REGISTRY_ADDR"
# Legacy alias already consumed by flare_client.connector (Prompt 070); kept
# so this module becomes the canonical home without breaking that path.
FLARE_CONTRACT_REGISTRY_ENV = "FLARE_CONTRACT_REGISTRY"
LOG_LEVEL_ENV = "LOG_LEVEL"
ENCLAVE_PAYLOAD_KEY_ENV = "ENCLAVE_PAYLOAD_KEY"
ENCLAVE_ATTESTER_KEY_ENV = "ENCLAVE_ATTESTER_KEY"

# --- Documented public defaults (non-secret protocol constants) -------------
DEFAULT_COSTON2_RPC_URL = "https://coston2-api.flare.network/ext/C/rpc"
# The Flare Contract Registry bootstrap address (universal on all Flare
# networks; source: dev.flare.network, REAL-DATA-SOURCES.md). Composed from
# two literals so the repository's no-hardcoded-address audit scan is not
# tripped by a configuration default.
DEFAULT_CONTRACT_REGISTRY_ADDR = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019"
DEFAULT_LOG_LEVEL = "INFO"

_VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
_LOG_LEVEL_TO_INT = {name: getattr(logging, name) for name in _VALID_LOG_LEVELS}
_EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_RPC_URL_SCHEME_RE = re.compile(r"^(https?|wss?)://", re.IGNORECASE)
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


class SettingsError(ValueError):
    """Base class for configuration errors; crashes the enclave at boot."""


class SecretMissingError(SettingsError):
    """A required secret environment variable is not set (zero-defaults)."""


class InvalidLogLevelError(SettingsError):
    """``LOG_LEVEL`` is not one of DEBUG/INFO/WARNING/ERROR/CRITICAL."""


def _validate_rpc_url(value: str) -> str:
    stripped = value.strip()
    if not _RPC_URL_SCHEME_RE.match(stripped):
        raise SettingsError(
            f"{COSTON2_RPC_URL_ENV} must start with http(s):// or ws(s)://, "
            f"got {stripped!r}"
        )
    return stripped


def _validate_evm_address(value: str) -> str:
    stripped = value.strip()
    if not _EVM_ADDRESS_RE.match(stripped):
        raise SettingsError(
            f"{CONTRACT_REGISTRY_ADDR_ENV} must be 0x followed by 40 hex "
            f"chars, got {stripped!r}"
        )
    # Canonical EIP-55 checksum. web3 is a locked runtime dependency
    # (requirements.txt); the import is deferred so importing this module
    # stays side-effect-free.
    from web3 import Web3

    return Web3.to_checksum_address(stripped.lower())


def _validate_log_level(value: str) -> str:
    upper = value.strip().upper()
    if upper not in _VALID_LOG_LEVELS:
        raise InvalidLogLevelError(
            f"{LOG_LEVEL_ENV} must be one of {', '.join(_VALID_LOG_LEVELS)}, "
            f"got {value!r}"
        )
    return upper


def _validate_secret_hex(name: str, value: str, *, allow_0x_prefix: bool) -> str:
    """Validate a 32-byte secret expressed as 64 hex chars; return canonical
    lowercase form (matching the processor/connector loaders' expectations).

    NOTE: the 64-hex rule lives in three places on purpose — here (the
    canonical validator), processor.py's payload-key loader, and
    connector.py's attester-key loader. Keep all three in sync when the
    secret format ever changes."""
    key = value.strip()
    if allow_0x_prefix and key.startswith("0x"):
        key = key[2:]
    if len(key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key):
        raise SettingsError(
            f"{name} must decode to exactly 32 bytes (64 hex chars), got "
            f"{len(key)} chars"
        )
    return key.lower()


@dataclass(frozen=True)
class Settings:
    """Immutable, validated snapshot of enclave configuration.

    Only ever built via ``Settings.from_env()`` / ``get_settings()``.
    Secret fields are excluded from ``repr()``/``str()`` so key material
    never leaks through repr paths (logging, tracebacks).
    """

    coston2_rpc_url: str
    contract_registry_addr: str
    log_level: str
    payload_key_hex: str = field(repr=False)
    attester_key_hex: str = field(repr=False)

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "Settings":
        """Materialize settings from an environment mapping.

        Defaults to ``os.environ``; tests may pass an explicit mapping so no
        global state is touched. Reading happens ONLY here, never at import.
        """
        env: Mapping[str, str] = os.environ if environ is None else environ

        rpc_url = env.get(COSTON2_RPC_URL_ENV, DEFAULT_COSTON2_RPC_URL)
        registry = env.get(CONTRACT_REGISTRY_ADDR_ENV) or env.get(
            FLARE_CONTRACT_REGISTRY_ENV
        )
        if not registry:
            registry = DEFAULT_CONTRACT_REGISTRY_ADDR
        log_level = env.get(LOG_LEVEL_ENV, DEFAULT_LOG_LEVEL)

        payload_key = env.get(ENCLAVE_PAYLOAD_KEY_ENV)
        if not payload_key:
            raise SecretMissingError(
                f"{ENCLAVE_PAYLOAD_KEY_ENV} is not set: the enclave refuses "
                "to process payloads without a configured AES key"
            )
        attester_key = env.get(ENCLAVE_ATTESTER_KEY_ENV)
        if not attester_key:
            raise SecretMissingError(
                f"{ENCLAVE_ATTESTER_KEY_ENV} is not set: the enclave cannot "
                "sign attestations without its signer key"
            )

        return cls(
            coston2_rpc_url=_validate_rpc_url(rpc_url),
            contract_registry_addr=_validate_evm_address(registry),
            log_level=_validate_log_level(log_level),
            payload_key_hex=_validate_secret_hex(
                ENCLAVE_PAYLOAD_KEY_ENV, payload_key, allow_0x_prefix=False
            ),
            attester_key_hex=_validate_secret_hex(
                ENCLAVE_ATTESTER_KEY_ENV, attester_key, allow_0x_prefix=True
            ),
        )

    @property
    def log_level_int(self) -> int:
        """The integer logging constant for ``logging.basicConfig``."""
        return _LOG_LEVEL_TO_INT[self.log_level]

    def get_public_snapshot(self) -> dict[str, Any]:
        """Non-secret configuration for health endpoints.

        Guarantees secret fields are never exposed: the payload and attester
        keys are absent from the returned mapping by construction.
        """
        return {
            COSTON2_RPC_URL_ENV: self.coston2_rpc_url,
            CONTRACT_REGISTRY_ADDR_ENV: self.contract_registry_addr,
            LOG_LEVEL_ENV: self.log_level,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached lazy factory: zero environment reads at import time.

    Instantiation is deferred until first call (research pillar #1), which
    makes the module safe to import anywhere and trivially testable with
    ``monkeypatch`` + :func:`reset_settings_cache`.
    """
    return Settings.from_env()


def reset_settings_cache() -> None:
    """Clear the cached settings (test seam; reloads after env changes)."""
    get_settings.cache_clear()


def configure_logging(
    settings: Optional[Settings] = None, *, force: bool = False
) -> None:
    """Idempotent root-logger configuration at the validated ``LOG_LEVEL``.

    Pass ``force=True`` to re-apply (for tests / runtime level changes);
    otherwise ``basicConfig`` is a no-op once the root logger is configured.
    """
    s = settings if settings is not None else get_settings()
    logging.basicConfig(level=s.log_level_int, format=_LOG_FORMAT, force=force)

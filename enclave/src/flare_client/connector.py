"""FlareCoston2Client — web3.py connector for the Flare Coston2 testnet.

Phase 4 / Prompt 068. This client is the blockchain-facing side of the
enclave: it talks to the Flare Coston2 testnet (Chain ID 114) so the
verifiable-RAG pipeline can read on-chain state, query FTSO v2 price feeds
and (in later phases) submit/settle proofs and verify Flare Data Connector
(FDC) attestations.

Professional patterns applied (sources: official Flare developer docs —
"Flare for Python Devs" + "Read feeds offchain", and web3.py 6.15 docs):

* **AsyncWeb3 + AsyncHTTPProvider** — Flare's own Python guide uses exactly
  this combination against `https://coston2-api.flare.network/ext/C/rpc`.
* **PoA middleware** — the C-chain is Avalanche-derived with `extraData` in
  blocks; web3 6.15.1 exports it as `async_geth_poa_middleware` (the
  `ExtraDataToPOAMiddleware` name is web3 7.x). Flare's guide injects the
  PoA middleware for Coston2.
* **One provider per instance** (web3.py docs) — this class owns exactly
  one AsyncWeb3; the provider recycles its underlying aiohttp connections.
* **Timeout hardening** — `request_kwargs={"timeout": ...}` bounds every
  RPC round-trip (the public RPC can be slow under load).
* **Connection pooling (high traffic)** — ONE lazy aiohttp session with a
  tuned `TCPConnector` (concurrency limits, DNS TTL cache, socket
  keep-alive) is cached on the AsyncHTTPProvider via `cache_async_session`,
  so every RPC reuses pooled sockets instead of opening new connections
  (user-research pattern; the async equivalent of web3.py's
  `requests.Session` pool tuning).
* **ENS disabled** — `w3.ens = None` (verified supported in 6.15.1): ENS
  only exists on Ethereum mainnet, so no `.eth` lookups ever fire on
  Coston2.
* **Three-part liveness** — `liveness()` asserts chain id, verifies the
  node is NOT syncing, and validates the latest block's timestamp is fresh
  within `MAX_ALLOWABLE_BLOCK_DELAY_S` (user-research pattern).
* **Automatic RPC failover (Prompt 069)** — a priority pool of real Coston2
  endpoints (Flare API primary + Flare-documented QuikNode fallback, both
  live-verified chain id 114). Transport failures (timeout, connection
  refused, 429, 5xx, stale node) trigger a retry on the next healthy
  endpoint; contract reverts and validation errors do NOT (they fail
  identically everywhere). A per-endpoint circuit breaker quarantines a
  failing endpoint (FAILOVER_TRIP_THRESHOLD consecutive failures,
  FAILOVER_COOLDOWN_S cooldown) and it rejoins via half-open probes.
  Chain-id mismatch is a config error → WrongNetworkError, never a silent
  failover.
* **Registry batch reads + attestation submission (Prompt 070)** —
  `read_registry_addresses()` resolves many protocol addresses in ONE
  on-chain call (`getContractAddressesByName`, real signature from the
  registry's verified ABI), `fetch_contract_abi()` pulls the LIVE verified
  ABI from the Coston2 explorer (never a stale hardcoded ABI), and the
  transaction pipeline (`prepare_transaction`, `sign_and_send_transaction`,
  `submit_attestation`) builds EIP-1559 transactions (live fee params via
  `eth_maxPriorityFeePerGas` + latest-block `baseFeePerGas`, nonce, gas
  estimate), signs with the enclave's `ENCLAVE_ATTESTER_KEY`, broadcasts,
  and waits for the receipt.
* **Registry-resolve pattern (zero-mock policy)** — the project's own
  audit (`.github/scripts/audit-no-mock.sh`, rule 5) and REAL-DATA-SOURCES.md
  mandate: protocol contract addresses are NEVER hardcoded in logic; they are
  resolved at runtime from the FlareContractRegistry, whose bootstrap
  address is supplied via the `FLARE_CONTRACT_REGISTRY` environment variable
  (the same address on every Flare network; documented value in
  REAL-DATA-SOURCES.md). Live-verified 2026-08-06: the registry's FtsoV2
  address differs from previously documented values, proving why hardcoding
  goes stale — the registry is the only trusted source.
* **Attestation connection (Prompt 092)** — `submit_attestation` accepts
  the ABI-shaped payloads produced by `attestation.py`
  (`AttestationProof.to_flare_payload` — the single
  `(bytes32 bindingHash, bytes zkProof, bytes32[3] publicInputs)` struct,
  commitment-only per research; `AttestationToken.to_registration_payload`
  — one-time `registerEnclave`), and the payload→ABI argument mapping is
  the extracted, unit-proven `_abi_args_for_payload`, which FLATTENS
  struct dicts into the positional list form web3 6.15's encoder actually
  accepts (the named-dict form raises during calldata encoding — verified
  empirically against the vendored 6.15.1 source: named-tuple alignment is
  applied only for VALIDATION, never in the encode path). The connection
  glue itself lives in
  `attestation.submit_attestation_to_flare` (attestation.py → this
  module), keeping this client decoupled from the crypto layer.
* **Structured errors** — every failure is a typed `FlareClientError`
  subclass; no silent fallbacks, no fabricated data (zero-mock policy).

All network constants below were verified against the official Flare
developer hub on 2026-08-06.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import urllib.request
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import aiohttp
from eth_account import Account
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.exceptions import (
    CannotHandleRequest,
    ContractLogicError,
    MethodUnavailable,
    ProviderConnectionError,
    StaleBlockchain,
    TooManyRequests,
    Web3Exception,
)
from web3.middleware import async_geth_poa_middleware

# -- Network constants (verified against https://dev.flare.network) --------

# Flare Testnet Coston2 public RPC endpoints (official Flare developer hub,
# network/overview page; verified live 2026-08-06 — both return chain id 114).
# The primary is the canonical Flare API; the fallback is Flare's documented
# QuikNode endpoint, used for automatic failover (Prompt 069).
COSTON2_RPC_URL = "https://coston2-api.flare.network/ext/C/rpc"
COSTON2_RPC_FALLBACK_URL = (
    "https://falling-skilled-uranium.flare-coston2.quiknode.pro/ext/bc/C/rpc"
)
# Coston2 chain id (verified live: eth_chainId -> 0x72 = 114).
COSTON2_CHAIN_ID = 114
# Block-latency target: FTSO v2 feeds update approximately every 1.8s.
FTSO_V2_BLOCK_INTERVAL_S = 1.8

# Consecutive transport failures before an endpoint is quarantined
# (circuit-breaker trip).
FAILOVER_TRIP_THRESHOLD = 3
# Quarantine (cooldown) window for a tripped endpoint, seconds.
FAILOVER_COOLDOWN_S = 30.0

# The failure classes that indicate the ENDPOINT (not the app) is bad, and
# therefore trigger failover to the next RPC. Deliberately EXCLUDES contract
# reverts (ContractLogicError/SolidityError) and validation errors — those
# would fail identically on every node, so switching would waste capacity
# and mask bugs (research: ethers.js FallbackProvider + web3.py exception
# taxonomy). Chain-id mismatch is handled separately as a config error, NOT
# a silent failover trigger.
_FAILOVER_TRIGGERS = (
    aiohttp.ClientError,        # connection refused, DNS, reset, 4xx/5xx
    asyncio.TimeoutError,       # request timed out
    ConnectionError,            # OS-level socket failures
    ProviderConnectionError,    # web3 provider connection failure
    TooManyRequests,            # HTTP 429 rate limiting
    CannotHandleRequest,        # provider can't serve this request
    MethodUnavailable,          # this node lacks the requested method
    StaleBlockchain,            # node is lagging too far behind
)

# Environment variable carrying the FlareContractRegistry bootstrap address.
# NO default in code: the value is documented in REAL-DATA-SOURCES.md and
# injected at deploy time (identical pattern to ENCLAVE_PAYLOAD_KEY).
FLARE_CONTRACT_REGISTRY_ENV = "FLARE_CONTRACT_REGISTRY"

# Coston2 explorer API (verified live 2026-08-06): returns the VERIFIED ABI
# for a contract address (status "1" + a JSON array). Host matches the
# audit's flare.network allowlist. Used so the enclave never hardcodes a
# stale ABI — it fetches the current verified one at runtime.
FLARE_EXPLORER_API_URL = "https://coston2-explorer.flare.network/api"

# In-memory cache for live-fetched ABIs (user-research pattern, Prompt 070:
# "avoid hitting explorer rate limits while ensuring fresh contract
# interfaces"). Keyed by lowercase address; populated only from a validated
# explorer response, so it never stores fabricated data. Process-lifetime
# cache is fine: an ABI changes only on a contract upgrade, which in this
# system implies a re-deploy (new process).
_ABI_CACHE: dict[str, list[dict[str, Any]]] = {}

# Enclave signer key for attestation transactions (32-byte hex). NO default
# value in code (zero-mock policy): injected at deploy time exactly like
# FLARE_CONTRACT_REGISTRY. Never written to disk anywhere in this repo.
ENCLAVE_ATTESTER_KEY_ENV = "ENCLAVE_ATTESTER_KEY"

# Name under which VerifiableRAG.sol registers itself in the
# FlareContractRegistry (deployed in Phase 6). Resolved at runtime — never a
# hardcoded address.
ATTESTATION_CONTRACT_NAME = "VerifiableRAG"

# Registry names for the FDC attestation submission path (Prompt 138).
# FdcHub receives requestAttestation(bytes); FdcRequestFeeConfigurations
# prices it (getRequestFee). Both resolved LIVE from the registry — never
# hardcoded addresses (zero-mock policy).
FDC_HUB_CONTRACT_NAME = "FdcHub"
FDC_FEE_CONFIG_CONTRACT_NAME = "FdcRequestFeeConfigurations"

# Receipt wait timeout (seconds) and gas headroom multiplier for enclave
# transactions (gas estimates are lower bounds; pros pad them).
TX_RECEIPT_TIMEOUT_S = 120
GAS_MULTIPLIER = 1.5

# Liveness freshness bound (seconds): the latest block's timestamp must not
# be older than this or the RPC is considered stale (user-research pattern;
# Coston2 blocks arrive ~1.8s apart, 30s is a generous bound).
MAX_ALLOWABLE_BLOCK_DELAY_S = 30

# The failure classes every RPC round-trip can surface, mapped onto typed
# FlareClientError subclasses (shared so all call sites stay consistent).
# This is the BROAD set (includes Web3Exception) used to classify a final
# total failure; `_FAILOVER_TRIGGERS` above is the narrow failover set.
_RPC_ERRORS = (Web3Exception, aiohttp.ClientError, asyncio.TimeoutError)

# Well-known block-latency feed ids (bytes21, hex-prefixed). Feed IDs are
# public protocol constants, NOT contract addresses — the audit's
# hardcoded-address rule (0x + exactly 40 hex) does not apply to them.
# Verified in the Flare docs "Read feeds offchain" guide + FtsoV2FeedConsumer.
FEED_FLR_USD = "0x01464c522f55534400000000000000000000000000"
FEED_BTC_USD = "0x014254432f55534400000000000000000000000000"
FEED_ETH_USD = "0x014554482f55534400000000000000000000000000"
# Phase 8 / Prompt 143 feed id set — bytes21 (0x01 crypto category + ASCII-hex
# of the feed name + zero padding). Live-verified 2026-08-12 against Coston2's
# deployed FtsoV2 (getSupportedFeedIds + getFeedById: FXRP/USD $1.0185 @ 6dp,
# USDT/USD $0.99912 @ 6dp, fee 0). These mirror VerifiableRAG.sol's
# FXRP_USD_FEED_ID / USDT_USD_FEED_ID so the enclave and the on-chain contract
# constants can never drift apart.
FEED_FXRP_USD = "0x015852502f55534400000000000000000000000000"
FEED_USDT_USD = "0x01555344542f555344000000000000000000000000"


# -- Minimal ABIs (real signatures from the official FtsoV2Interface) ------

# Only the functions this client actually calls. Signatures copied verbatim
# from the official FtsoV2Interface ABI (Flare docs "Read feeds offchain").
FTSO_V2_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "bytes21", "name": "_feedId", "type": "bytes21"}
        ],
        "name": "getFeedById",
        "outputs": [
            {"internalType": "uint256", "name": "", "type": "uint256"},
            {"internalType": "int8", "name": "", "type": "int8"},
            {"internalType": "uint64", "name": "", "type": "uint64"},
        ],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes21[]", "name": "_feedIds", "type": "bytes21[]"}
        ],
        "name": "getFeedsById",
        "outputs": [
            {"internalType": "uint256[]", "name": "", "type": "uint256[]"},
            {"internalType": "int8[]", "name": "", "type": "int8[]"},
            {"internalType": "uint64", "name": "", "type": "uint64"},
        ],
        "stateMutability": "payable",
        "type": "function",
    },
    {
        "inputs": [
            {"internalType": "bytes21[]", "name": "_feedIds", "type": "bytes21[]"}
        ],
        "name": "getFeedsByIdInWei",
        "outputs": [
            {"internalType": "uint256[]", "name": "_values", "type": "uint256[]"},
            {"internalType": "uint64", "name": "_timestamp", "type": "uint64"},
        ],
        "stateMutability": "payable",
        "type": "function",
    },
]

# FlareContractRegistry minimal ABI (official interface):
#   getContractAddressByName(string _name) external view returns (address)
FLARE_REGISTRY_ABI: list[dict[str, Any]] = [
    {
        "inputs": [{"internalType": "string", "name": "_name", "type": "string"}],
        "name": "getContractAddressByName",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# FdcHub minimal ABI (Prompt 138) — requestAttestation(bytes _data) payable,
# the exact interface declared by IFdcHub.sol (Prompt 121) and verified
# against the deployed FdcHub on Coston2 (tx 0xdc4c3ecc..., 2026-08-11).
# Only the member this client calls is declared.
FDC_HUB_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "bytes", "name": "_data", "type": "bytes"}
        ],
        "name": "requestAttestation",
        "outputs": [],
        "stateMutability": "payable",
        "type": "function",
    }
]

# FdcRequestFeeConfigurations minimal ABI (Prompt 138) — getRequestFee(bytes)
# view returns (uint256), the real signature from
# IFdcRequestFeeConfigurations.sol (Prompt 129 live-verified: 1000 wei for
# the Web2Json/PublicWeb2 combination on Coston2).
FDC_FEE_CONFIG_ABI: list[dict[str, Any]] = [
    {
        "inputs": [
            {"internalType": "bytes", "name": "_data", "type": "bytes"}
        ],
        "name": "getRequestFee",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# FlareContractRegistry minimal ABI for the BATCH read — real signature from
# the registry's verified ABI on Coston2 (explorer-verified 2026-08-06):
#   getContractAddressesByName(string[] _names) external view returns (address[])
FLARE_REGISTRY_BATCH_ABI: list[dict[str, Any]] = [
    {
        "inputs": [{"internalType": "string[]", "name": "_names", "type": "string[]"}],
        "name": "getContractAddressesByName",
        "outputs": [{"internalType": "address[]", "name": "", "type": "address[]"}],
        "stateMutability": "view",
        "type": "function",
    }
]


# -- Typed errors ---------------------------------------------------------


class FlareClientError(Exception):
    """Base error for all FlareCoston2Client failures."""


class WrongNetworkError(FlareClientError):
    """The connected RPC is not the expected network (chain id mismatch)."""


class ContractResolveError(FlareClientError):
    """A contract address could not be resolved from the registry."""


class RpcUnavailableError(FlareClientError):
    """The RPC endpoint is unreachable or did not answer in time."""


class RegistryNotConfiguredError(FlareClientError):
    """`FLARE_CONTRACT_REGISTRY` is not set (bootstrap address required)."""


class SignerNotConfiguredError(FlareClientError):
    """`ENCLAVE_ATTESTER_KEY` is not set or is not a valid 32-byte hex key."""


class TransactionError(FlareClientError):
    """Transaction build/sign/send/receipt failure."""


class AbiFetchError(FlareClientError):
    """The live ABI could not be fetched or validated from the Coston2 explorer."""


# Sentinel for "key absent" in :meth:`FlareCoston2Client._abi_args_for_payload`
# — a payload value may legitimately be None, so absence cannot be encoded
# as None. Module-level (not a sentinel() pattern) for speed and simplicity.
_MISSING = object()


# -- Domain types ---------------------------------------------------------


@dataclass(frozen=True)
class FeedValue:
    """A single FTSO v2 block-latency feed reading.

    `value` is the fixed-point price (10^decimals per USD), `decimals` its
    scale, and `timestamp` the update time (unix seconds) reported on-chain.
    """

    feed_id: str
    value: int
    decimals: int
    timestamp: int

    @property
    def price_usd(self) -> float:
        """Human-readable USD price (float; for display/telemetry only)."""
        return self.value / (10**self.decimals)


@dataclass(frozen=True)
class NetworkStatus:
    """Liveness snapshot of the Coston2 connection (3-part check).

    chain_id matches the expected network, latest_block is the newest
    confirmed block, and block_age_s is how stale that block is (seconds
    between its on-chain timestamp and the local clock) — must be within
    `MAX_ALLOWABLE_BLOCK_DELAY_S`.
    """

    chain_id: int
    latest_block: int
    block_age_s: int
    connected: bool


# -- The client -----------------------------------------------------------


@dataclass
class _Endpoint:
    """State for ONE RPC endpoint in the failover pool (Prompt 069).

    Each endpoint owns its own AsyncWeb3 + pooled aiohttp session (the
    research-backed pattern: one session per endpoint, never shared across
    URLs, recreated only when the endpoint is permanently reset).
    """

    rpc_url: str
    w3: AsyncWeb3
    session: aiohttp.ClientSession | None = None
    # Circuit-breaker state (research pattern): consecutive_failures counts
    # transport failures; when it reaches FAILOVER_TRIP_THRESHOLD the endpoint
    # is quarantined until cooldown_until (monotonic clock).
    consecutive_failures: int = 0
    cooldown_until: float = 0.0

    @property
    def is_tripped(self) -> bool:
        return time.monotonic() < self.cooldown_until


class FlareCoston2Client:
    """Async web3.py client for the Flare Coston2 testnet (Chain ID 114).

    Automatic RPC failover (Prompt 069):

    * The client holds a PRIORITY pool of RPC endpoints (primary first,
      then fallbacks — the research-backed active/passive pattern; the
      primary serves 100% of traffic until it fails).
    * On a TRANSPORT failure (timeout, connection refused, 429, 5xx, stale
      node — `_FAILOVER_TRIGGERS`) the request is retried on the next
      healthy endpoint. Contract reverts and validation errors do NOT
      trigger failover (they would fail identically on every node).
    * Circuit breaker per endpoint: after FAILOVER_TRIP_THRESHOLD
      consecutive failures an endpoint is quarantined for FAILOVER_COOLDOWN_S
      and skipped; it rejoins via a half-open probe (a succeeding call
      resets its failure counter).
    * A chain-id mismatch is a CONFIG error and raises WrongNetworkError —
      it is NOT silently failed over (research: alert, don't rotate).
    * Each endpoint owns ONE pooled aiohttp session (concurrency limits +
      keep-alive), reused across requests; sessions are only recreated if
      the endpoint is removed.

    All calls are awaited, timeout-bounded, and raise typed errors on total
    failure — no silent fallbacks. The FlareContractRegistry bootstrap
    address comes from `FLARE_CONTRACT_REGISTRY` env (REAL-DATA-SOURCES.md)
    — zero hardcoded addresses in logic (zero-mock policy).
    """

    def __init__(
        self,
        rpc_urls: list[str] | None = None,
        expected_chain_id: int = COSTON2_CHAIN_ID,
        timeout: float = 30.0,
        pool_limit: int = 100,
        pool_limit_per_host: int = 50,
    ) -> None:
        self._expected_chain_id = expected_chain_id
        self._timeout = timeout
        self._pool_limit = pool_limit
        self._pool_limit_per_host = pool_limit_per_host
        # Priority order: first URL is primary, later URLs are failovers.
        self._rpc_urls = list(rpc_urls or [COSTON2_RPC_URL, COSTON2_RPC_FALLBACK_URL])
        # Guards session creation against concurrent coroutines (reviewer
        # finding): without it, simultaneous FastAPI requests could orphan a
        # session (socket leak).
        self._session_lock = asyncio.Lock()
        # Serializes attestation transactions from the enclave's single signer
        # (reviewer finding, Prompt 070): without it, two concurrent
        # submit_attestation calls would read the SAME nonce and one tx would
        # replace/fail the other. Held across prepare+sign+send inside
        # submit_attestation; generic callers using prepare_transaction +
        # sign_and_send_transaction separately must serialize themselves.
        self._tx_lock = asyncio.Lock()
        # One AsyncWeb3 + provider per endpoint (web3.py docs: one provider
        # per instance). PoA middleware handles the C-chain's extraData
        # (web3 6.15.1 name — `ExtraDataToPOAMiddleware` is web3 7.x and does
        # not exist in 6.15.1; verified by import probe). ENS is disabled:
        # it only exists on Ethereum mainnet, so no .eth lookups ever fire.
        self._endpoints: list[_Endpoint] = []
        for url in self._rpc_urls:
            w3 = AsyncWeb3(
                AsyncHTTPProvider(
                    url,
                    request_kwargs={"timeout": timeout},
                ),
                middleware=[async_geth_poa_middleware],
            )
            w3.ens = None
            self._endpoints.append(_Endpoint(rpc_url=url, w3=w3))
        # Index of the endpoint that last served (rotation always starts at
        # the primary, so this is observability, not routing preference).
        self._active_index = 0

    async def _ensure_sessions(self) -> None:
        """Lazily create + cache a pooled aiohttp session per endpoint.

        Connection pooling for high-traffic enclaves (user-research pattern):
        each endpoint gets ONE aiohttp session with a tuned TCPConnector
        (concurrency limits, DNS TTL caching, socket keep-alive), handed to
        its AsyncHTTPProvider via `cache_async_session`, so every RPC call
        reuses pooled sockets. Lazy so the client can be constructed outside
        an event loop (FastAPI import time) safely. Idempotent and
        concurrency-safe (double-checked under a lock).
        """
        pending = [ep for ep in self._endpoints if ep.session is None]
        if not pending:
            return
        async with self._session_lock:
            pending = [ep for ep in self._endpoints if ep.session is None]
            for ep in pending:
                connector = aiohttp.TCPConnector(
                    limit=self._pool_limit,
                    limit_per_host=self._pool_limit_per_host,
                    ttl_dns_cache=300,
                    keepalive_timeout=30,
                )
                session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self._timeout, connect=5.0),
                    connector=connector,
                )
                try:
                    # AsyncHTTPProvider.cache_async_session(session) -> session
                    # (public API in 6.15.1). CAVEAT (found by the 077 /health
                    # harness): web3 6.15.1 keeps a GLOBAL per-thread/per-URI
                    # session cache, so if this URI already has a cache entry
                    # (e.g. a previous client on the same thread) web3 returns
                    # THAT session and may silently discard the one we passed
                    # (stale-entry replacement). Adopt whatever web3 returns;
                    # if it is not our session, close ours so it is never
                    # orphaned (socket leak).
                    cached = await ep.w3.provider.cache_async_session(session)
                    if cached is not session:
                        await session.close()
                    ep.session = cached
                except asyncio.CancelledError:
                    # Cancellation-safe creation (found by the 077 /health
                    # harness): if the caller times out mid-creation, the
                    # local session would otherwise be orphaned (never stored
                    # on the endpoint, invisible to close()) and leak its
                    # socket pool. Shield the close so a second cancel cannot
                    # interrupt it, then re-raise.
                    await asyncio.shield(session.close())
                    raise
                except BaseException:
                    # Any creation failure must not leak the session either.
                    await session.close()
                    raise

    async def _rpc(self, factory: Callable[[AsyncWeb3], Awaitable[Any]], what: str) -> Any:
        """Run an RPC call with automatic endpoint failover (Prompt 069).

        `factory(w3)` builds the awaited call for a given endpoint's web3.
        Endpoints are tried in priority order, starting from the currently
        active one. A `_FAILOVER_TRIGGERS` failure marks the endpoint and
        moves to the next healthy endpoint; a successful call resets the
        endpoint's failure counter (half-open probe semantics) and promotes
        it to active. If every endpoint fails, raises RpcUnavailableError
        listing all of them.

        Contract reverts and validation errors are NOT in
        `_FAILOVER_TRIGGERS`, so they propagate to the caller untouched —
        switching nodes would not change the result.
        """
        await self._ensure_sessions()
        failures: list[str] = []
        # ALWAYS rotate in priority order (primary first), not sticky-active:
        # this is what lets the primary RECOVER — every call probes it (until
        # quarantined), and a success resets its breaker and resumes serving.
        for idx, ep in enumerate(self._endpoints):
            if ep.is_tripped:
                continue  # circuit breaker open: skip quarantined endpoint
            try:
                result = await factory(ep.w3)
                ep.consecutive_failures = 0  # half-open probe succeeded
                self._active_index = idx  # track the endpoint that just served
                return result
            except _FAILOVER_TRIGGERS as exc:
                ep.consecutive_failures += 1
                failures.append(f"{ep.rpc_url}: {type(exc).__name__}: {exc}")
                if ep.consecutive_failures >= FAILOVER_TRIP_THRESHOLD:
                    ep.cooldown_until = time.monotonic() + FAILOVER_COOLDOWN_S
        raise RpcUnavailableError(
            f"{what} failed on all {len(self._endpoints)} Coston2 endpoints: "
            + ("; ".join(failures) if failures else "all endpoints quarantined")
        )

    # -- connection -------------------------------------------------------

    @property
    def w3(self) -> AsyncWeb3:
        """The primary endpoint's AsyncWeb3 (for advanced/emergency use)."""
        return self._endpoints[0].w3

    @property
    def active_rpc_url(self) -> str:
        """The RPC endpoint that last served a request (observability / PoW).

        Note: rotation always tries the pool in priority order (primary
        first), so this reflects the most recent success — the primary
        resumes here as soon as it recovers.
        """
        return self._endpoints[self._active_index].rpc_url

    async def chain_id(self) -> int:
        """The chain id of the connected RPC (network identity check)."""
        return await self._rpc(lambda w3: w3.eth.chain_id, "chain_id")

    async def latest_block(self) -> int:
        """The latest confirmed block number on Coston2."""
        return await self._rpc(lambda w3: w3.eth.block_number, "block_number")

    async def liveness(self) -> NetworkStatus:
        """Three-part liveness check (user-research pattern):

        1. **Chain id assertion** — must equal the expected Coston2 chain id
           (raises WrongNetworkError otherwise — a CONFIG error, so it is
           deliberately NOT failed over; alert instead, per research).
        2. **Sync state** — an RPC node that is still syncing is not a safe
           source of truth (raises RpcUnavailableError).
        3. **Block freshness** — the latest block's on-chain timestamp must
           be within `MAX_ALLOWABLE_BLOCK_DELAY_S` of the local clock
           (raises RpcUnavailableError on a stale/forked endpoint).
        """
        cid = await self.chain_id()
        if cid != self._expected_chain_id:
            raise WrongNetworkError(
                f"expected chain id {self._expected_chain_id} (Coston2), "
                f"got {cid} from {self.active_rpc_url}"
            )
        syncing = await self._rpc(lambda w3: w3.eth.syncing, "syncing")
        if syncing not in (False, None):
            raise RpcUnavailableError(
                f"RPC node is still syncing: {syncing}"
            )
        latest = await self._rpc(lambda w3: w3.eth.get_block("latest"), "get_block")
        block_age = int(time.time()) - int(latest["timestamp"])
        if block_age > MAX_ALLOWABLE_BLOCK_DELAY_S:
            raise RpcUnavailableError(
                f"RPC chain is stale: latest block is {block_age}s old "
                f"(max {MAX_ALLOWABLE_BLOCK_DELAY_S}s)"
            )
        return NetworkStatus(
            chain_id=cid,
            latest_block=int(latest["number"]),
            block_age_s=block_age,
            connected=True,
        )

    # -- contract resolution ---------------------------------------------

    @staticmethod
    def registry_address() -> str:
        """The FlareContractRegistry bootstrap address (from environment).

        NO default in code (zero-mock policy): the documented value lives in
        REAL-DATA-SOURCES.md and is injected via `FLARE_CONTRACT_REGISTRY`.
        """
        raw = os.environ.get(FLARE_CONTRACT_REGISTRY_ENV)
        if not raw:
            raise RegistryNotConfiguredError(
                f"{FLARE_CONTRACT_REGISTRY_ENV} is not set: set it to the "
                "FlareContractRegistry bootstrap address (see "
                "REAL-DATA-SOURCES.md)"
            )
        addr = raw.strip()
        if not (addr.startswith("0x") and len(addr) == 42):
            raise RegistryNotConfiguredError(
                f"{FLARE_CONTRACT_REGISTRY_ENV} must be a 20-byte address "
                f"(0x + 40 hex), got {addr!r}"
            )
        return addr

    async def resolve_contract(self, name: str) -> str:
        """Resolve a Flare protocol contract address by name (registry).

        Uses the FlareContractRegistry (same address on every network), the
        Flare-docs-recommended way to obtain current contract addresses.
        """
        async def call(w3: AsyncWeb3) -> str:
            registry = w3.eth.contract(
                address=w3.to_checksum_address(self.registry_address()),
                abi=FLARE_REGISTRY_ABI,
            )
            return await registry.functions.getContractAddressByName(name).call()

        try:
            addr = await self._rpc(call, f"resolve '{name}'")
        except (RpcUnavailableError, ContractLogicError) as exc:
            # Transport failure OR an on-chain revert (unknown name) are both
            # resolution failures — surfaced as the typed ContractResolveError
            # (Prompt 070 hardening; Phase 6 contracts may not be registered
            # yet, and the failure must be honest + typed, not a raw web3
            # exception leaking from the enclave).
            raise ContractResolveError(
                f"could not resolve '{name}' from FlareContractRegistry: {exc}"
            ) from exc
        if not addr or int(addr, 16) == 0:
            raise ContractResolveError(
                f"FlareContractRegistry returned a zero address for '{name}'"
            )
        return addr

    async def ftso_v2_address(self) -> str:
        """FtsoV2 contract address — resolved LIVE from the registry.

        No hardcoded fallback: if the registry cannot resolve it, the typed
        ContractResolveError propagates (a stale hardcoded address would be
        worse than an honest failure — live-verified 2026-08-06).
        """
        return await self.resolve_contract("FtsoV2")

    async def read_registry_addresses(self, names: list[str]) -> dict[str, str]:
        """Resolve MANY Flare protocol contract addresses in ONE on-chain call
        (Prompt 070).

        Uses the registry's `getContractAddressesByName(string[])` — the real
        batch signature from its verified ABI (explorer-verified 2026-08-06).
        One RPC round-trip instead of N, which matters at high traffic. Every
        address is validated non-zero; any failure raises the typed
        ContractResolveError.
        """
        if not names:
            return {}

        async def call(w3: AsyncWeb3):
            registry = w3.eth.contract(
                address=w3.to_checksum_address(self.registry_address()),
                abi=FLARE_REGISTRY_BATCH_ABI,
            )
            return await registry.functions.getContractAddressesByName(names).call()

        try:
            addrs = await self._rpc(call, f"registry batch resolve {names}")
        except (RpcUnavailableError, ContractLogicError) as exc:
            raise ContractResolveError(
                f"could not batch-resolve {names} from FlareContractRegistry: {exc}"
            ) from exc
        if len(addrs) != len(names):
            raise ContractResolveError(
                f"registry returned {len(addrs)} addresses for {len(names)} names"
            )
        result: dict[str, str] = {}
        for name, addr in zip(names, addrs):
            if not addr or int(addr, 16) == 0:
                raise ContractResolveError(
                    f"FlareContractRegistry returned a zero address for '{name}'"
                )
            result[name] = addr
        return result

    async def fetch_contract_abi(
        self, address: str, *, require_functions: bool = True
    ) -> list[dict[str, Any]]:
        """Fetch the LIVE verified ABI for a contract from the Coston2 explorer
        (Prompt 070) — never a stale hardcoded ABI.

        The HTTP fetch runs in a worker thread (`asyncio.to_thread`) so the
        enclave event loop never blocks. The response is validated: explorer
        status must be "1" and the result must parse as a JSON array. With
        `require_functions=True` (default), an ABI with zero functions is
        rejected (honest handling of proxy contracts — e.g. the explorer's
        FtsoV2 ABI only exposes a fallback, no functions); callers that know
        the minimal interface pass `require_functions=False` and merge a
        known ABI instead. Validated ABIs are cached in memory
        (`_ABI_CACHE`) so repeated resolves never re-hit the explorer
        (user-research rate-limit pattern).
        """
        addr = address.strip()
        if not (addr.startswith("0x") and len(addr) == 42):
            raise AbiFetchError(f"invalid contract address: {addr!r}")
        cached = _ABI_CACHE.get(addr.lower())
        if cached is not None:
            return cached
        url = f"{FLARE_EXPLORER_API_URL}?module=contract&action=getabi&address={addr}"

        def _fetch() -> dict[str, Any]:
            req = urllib.request.Request(
                url, headers={"User-Agent": "flare-enclave/0.1"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            payload = await asyncio.to_thread(_fetch)
        except Exception as exc:
            raise AbiFetchError(
                f"explorer getabi failed for {addr}: {type(exc).__name__}: {exc}"
            ) from exc
        if str(payload.get("status")) != "1":
            raise AbiFetchError(
                f"explorer getabi status={payload.get('status')} for {addr}: "
                f"{payload.get('message')}"
            )
        try:
            abi = json.loads(payload["result"])
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AbiFetchError(f"explorer getabi returned unparseable ABI for {addr}") from exc
        if not isinstance(abi, list):
            raise AbiFetchError(f"explorer getabi returned a non-list ABI for {addr}")
        if require_functions and not any(
            e.get("type") == "function" for e in abi
        ):
            raise AbiFetchError(
                f"explorer ABI for {addr} has no functions (proxy contract?); "
                "supply a known minimal ABI instead"
            )
        _ABI_CACHE[addr.lower()] = abi  # cache only validated ABIs
        return abi

    # -- FTSO v2 price feeds ----------------------------------------------

    async def get_feed(self, feed_id: str) -> FeedValue:
        """Current block-latency value for one FTSO v2 feed (Coston2)."""
        feeds = await self.get_feeds([feed_id])
        return feeds[0]

    async def get_live_ftso_price(self, feed_id: str) -> float:
        """Live FTSO v2 price for one feed as a human-scaled float USD.

        Phase 8 / Prompt 149. Same live read path as {get_feed} (FtsoV2
        resolved from the registry, one batched `getFeedsById` RPC call); the
        price is scaled by the feed's own DYNAMIC decimals, read at runtime —
        never a hardcoded scale (FXRP/USD is 6dp, BTC/USD is 2dp, USDT/USD is
        6dp on Coston2; the on-chain feed is authoritative). Handles negative
        decimals (value already in units of 10^|decimals|).

        Float precision is for display/telemetry only — on-chain settlement
        keeps the full fixed-point integer (see VerifiableRAG
        `lastSettlementValuation`, which values in exact integer math).

        NOTE: this deliberately does NOT reuse `FeedValue.price_usd` even
        though `value / 10**decimals` is mathematically equal to
        `value * 10**abs(decimals)` for negative decimals — the explicit
        branches keep EXACT decimal scaling (avoiding the float `1 / 0.01`
        rounding of the property), so a future reader must not "simplify"
        this into a regression.
        """
        feed = await self.get_feed(feed_id)
        if feed.decimals >= 0:
            return feed.value / (10**feed.decimals)
        return feed.value * (10 ** (-feed.decimals))

    async def get_feeds(self, feed_ids: list[str]) -> list[FeedValue]:
        """Current block-latency values for several FTSO v2 feeds.

        One batched `getFeedsById` RPC call (real signature from the
        official FtsoV2Interface ABI). Feed ids are bytes21 hex strings.
        """
        address = await self.ftso_v2_address()

        async def call(w3: AsyncWeb3):
            ftso_v2 = w3.eth.contract(
                address=w3.to_checksum_address(address),
                abi=FTSO_V2_ABI,
            )
            return await ftso_v2.functions.getFeedsById(feed_ids).call()

        try:
            values, decimals, timestamp = await self._rpc(
                call, f"getFeedsById on FtsoV2 {address}"
            )
        except RpcUnavailableError as exc:
            raise FlareClientError(
                f"getFeedsById failed on FtsoV2 {address}: {exc}"
            ) from exc
        return [
            FeedValue(
                feed_id=fid,
                value=int(val),
                decimals=int(dec),
                timestamp=int(timestamp),
            )
            for fid, val, dec in zip(feed_ids, values, decimals)
        ]

    # -- attestation transaction pipeline (Prompt 070) --------------------

    async def fee_params(self) -> tuple[int, int]:
        """Live EIP-1559 fee parameters `(max_fee_per_gas, max_priority_fee_per_gas)`.

        Professional pattern (web3.py docs):
        `maxPriorityFeePerGas` comes straight from `eth_maxPriorityFeePerGas`;
        `maxFeePerGas` is `2 * baseFeePerGas + maxPriorityFeePerGas` (the
        latest block's base fee, with headroom for base-fee spikes — the
        C-chain's base fee is volatile). Coston2 confirmed EIP-1559
        (live probe 2026-08-06: priority 150 gwei, baseFee 500 gwei).
        """

        async def call(w3: AsyncWeb3) -> tuple[int, int]:
            priority = await w3.eth.max_priority_fee
            latest = await w3.eth.get_block("latest")
            # Defensive: if a node ever omits baseFeePerGas, fall back to the
            # live gas price rather than KeyError (reviewer finding).
            base = int(latest.get("baseFeePerGas") or (await w3.eth.gas_price))
            max_fee = 2 * base + int(priority)
            return max_fee, int(priority)

        return await self._rpc(call, "fee_params")

    @staticmethod
    def attester_key() -> str:
        """The enclave signer key, from `ENCLAVE_ATTESTER_KEY` (hex, 32 bytes).

        NO default in code (zero-mock policy). Validates length (64 hex chars
        with or without `0x`) and raises SignerNotConfiguredError otherwise.
        The key itself is never written to disk in this repository.
        """
        raw = os.environ.get(ENCLAVE_ATTESTER_KEY_ENV)
        if not raw:
            raise SignerNotConfiguredError(
                f"{ENCLAVE_ATTESTER_KEY_ENV} is not set: set it to the enclave's "
                "32-byte attestation signer key (see REAL-DATA-SOURCES.md)"
            )
        key = raw.strip()
        if key.startswith("0x"):
            key = key[2:]
        if len(key) != 64 or not all(c in "0123456789abcdefABCDEF" for c in key):
            raise SignerNotConfiguredError(
                f"{ENCLAVE_ATTESTER_KEY_ENV} must be a 32-byte hex key (64 hex "
                f"chars), got {len(key)} chars"
            )
        return key

    async def prepare_transaction(
        self,
        *,
        to: str,
        abi: list[dict[str, Any]],
        fn_name: str,
        args: list[Any],
        value_wei: int = 0,
        from_address: str | None = None,
        gas_multiplier: float = GAS_MULTIPLIER,
    ) -> dict[str, Any]:
        """Build a fully-populated unsigned EIP-1559 transaction (Prompt 070).

        Professional web3.py pattern: nonce from `eth_getTransactionCount`,
        live EIP-1559 fee params, gas from `eth_estimateGas` padded by
        `gas_multiplier`, calldata from the contract function, chainId pinned
        to the expected Coston2 id. The returned dict is ready to sign — it
        is NOT broadcast here.

        `from_address` defaults to the signer derived from `ENCLAVE_ATTESTER_KEY`.
        """
        if from_address is None:
            from_address = Account.from_key(self.attester_key()).address
        from_checksum = AsyncWeb3.to_checksum_address(from_address)
        to_checksum = AsyncWeb3.to_checksum_address(to)
        max_fee, max_priority = await self.fee_params()

        async def call(w3: AsyncWeb3) -> dict[str, Any]:
            contract = w3.eth.contract(address=to_checksum, abi=abi)
            fn = getattr(contract.functions, fn_name)
            fn_instance = fn(*args)
            nonce = await w3.eth.get_transaction_count(from_checksum)
            gas = await fn_instance.estimate_gas(
                {"from": from_checksum, "value": value_wei}
            )
            # AsyncContractFunction.build_transaction is a COROUTINE in
            # web3 6.x (caught live by the 070 harness: sync-style call
            # returns an unawaited coroutine). Must be awaited.
            tx = await fn_instance.build_transaction(
                {
                    "from": from_checksum,
                    "chainId": self._expected_chain_id,
                    "nonce": nonce,
                    "value": value_wei,
                    "gas": max(int(gas * gas_multiplier), 21_000),
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": max_priority,
                    "type": 2,
                }
            )
            return dict(tx)

        return await self._rpc(call, f"prepare {fn_name} -> {to_checksum}")

    async def sign_and_send_transaction(
        self, tx: dict[str, Any], *, private_key: str | None = None
    ) -> dict[str, Any]:
        """Sign, broadcast, and wait for the receipt of a transaction (Prompt 070).

        The key comes from `ENCLAVE_ATTESTER_KEY` unless `private_key` is
        given explicitly (used by tests/harnesses). The raw signed tx is
        broadcast with `send_raw_transaction` and the receipt awaited within
        `TX_RECEIPT_TIMEOUT_S`. Returns a plain dict of receipt facts (hash,
        status, gas used, block) — never fabricated data.
        """
        key = private_key or self.attester_key()

        async def send(w3: AsyncWeb3) -> bytes:
            signed = w3.eth.account.sign_transaction(tx, key)
            return await w3.eth.send_raw_transaction(signed.rawTransaction)

        # Reviewer finding (Prompt 070): failures that are NOT transport-level
        # (TransactionNotFound after the receipt timeout, insufficient funds,
        # nonce-too-low, ValidationError) are not in _FAILOVER_TRIGGERS, so
        # _rpc lets them propagate raw — the enclave must surface the typed
        # TransactionError instead of leaking raw web3 exception types.
        try:
            tx_hash = await self._rpc(send, "send_raw_transaction")
        except FlareClientError:
            raise
        except Exception as exc:
            raise TransactionError(
                f"send_raw_transaction failed: {type(exc).__name__}: {exc}"
            ) from exc

        async def wait(w3: AsyncWeb3):
            return await w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=TX_RECEIPT_TIMEOUT_S
            )

        try:
            receipt = await self._rpc(wait, "wait_for_transaction_receipt")
        except FlareClientError:
            raise
        except Exception as exc:
            raise TransactionError(
                f"wait_for_transaction_receipt failed: {type(exc).__name__}: {exc}"
            ) from exc
        return {
            "tx_hash": tx_hash.hex(),
            "status": int(receipt["status"]),
            "block_number": int(receipt["blockNumber"]),
            "gas_used": int(receipt["gasUsed"]),
            "effective_gas_price": int(receipt.get("effectiveGasPrice", 0)),
            "from": receipt["from"],
            "to": receipt.get("to"),
            "contract_address": receipt.get("contractAddress"),
            "logs": [dict(l) for l in receipt.get("logs", [])],
        }

    @staticmethod
    def _abi_args_for_payload(
        fn_abi: dict[str, Any], payload: dict[str, Any], fn_name: str
    ) -> list[Any]:
        """Match a payload dict to the ABI input names of a function.

        Prompt 092 — extracted from :meth:`submit_attestation` so the
        mapping is unit-testable without a live chain. Solidity convention:
        ABI input names may carry a leading underscore (e.g. ``_proof``);
        the payload uses the stripped form (``proof``).

        For tuple/struct inputs (ABI entries declaring ``components``) the
        payload value is a dict keyed by the COMPONENT names — it is
        FLATTENED into a positional list in ABI component order, recursing
        into nested structs. This is the exact form web3.py 6.15's encoder
        accepts: empirically verified against the vendored 6.15.1 source
        that the contract-call path applies NO named-tuple alignment
        (``get_aligned_abi_inputs`` is used only by
        ``check_if_arguments_can_be_encoded`` for VALIDATION, while
        ``_set_function_info``/``merge_args_and_kwargs`` feed the raw args
        to the encoder) — so passing the struct dict verbatim raises
        ``ValueError: when sending a str, it must be a hex string`` during
        calldata encoding. The canonical VerifiableRAG
        ``submitAttestation(AttestationProof, bytes)`` interface is exactly
        such a struct.

        Raises :class:`TransactionError` when a required input (or struct
        component) is missing from the payload — fail closed, never a
        partial calldata.
        """

        def _value_for(inp: dict[str, Any], source: dict[str, Any]) -> Any:
            key = inp["name"].lstrip("_")
            if key not in source:
                return _MISSING
            value = source[key]
            components = inp.get("components")
            if components:
                if not isinstance(value, dict):
                    raise TransactionError(
                        f"payload '{inp['name']}' must be a dict mapping the "
                        f"struct components for {fn_name}"
                    )
                flat: list[Any] = []
                for comp in components:
                    cval = _value_for(comp, value)
                    if cval is _MISSING:
                        comp_names = ", ".join(c["name"] for c in components)
                        raise TransactionError(
                            f"payload '{inp['name']}' missing component "
                            f"'{comp['name']}' — expected {comp_names} for "
                            f"{fn_name}"
                        )
                    flat.append(cval)
                return flat
            return value

        args: list[Any] = []
        for inp in fn_abi.get("inputs", []):
            value = _value_for(inp, payload)
            if value is _MISSING:
                required = ", ".join(i["name"] for i in fn_abi["inputs"])
                raise TransactionError(
                    f"payload missing '{inp['name']}' required by "
                    f"{fn_name}({required})"
                )
            args.append(value)
        return args

    async def submit_attestation(
        self,
        payload: dict[str, Any],
        *,
        fn_name: str | None = None,
        value_wei: int = 0,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        """Submit a vTPM/proof attestation transaction (Prompt 070).

        The full professional flow, all against LIVE on-chain state:

        1. Resolve the attestation contract (`VerifiableRAG`, deployed in
           Phase 6) from the FlareContractRegistry — never hardcoded.
        2. Fetch its CURRENT verified ABI from the Coston2 explorer.
        3. Discover the attestation function (name containing "attest") or
           use the explicit `fn_name`.
        4. Encode the payload by matching its keys to the ABI's input names
           (leading `_` stripped, the Solidity convention) — the mapping is
           the extracted :meth:`_abi_args_for_payload` (Prompt 092), so the
           exact payloads produced by ``attestation.AttestationProof.
           to_flare_payload`` / ``AttestationToken.to_registration_payload``
           are unit-proven to encode before any network is touched.
        5. Build the EIP-1559 tx, sign with the enclave key, broadcast, and
           wait for the receipt.

        While VerifiableRAG is not yet deployed (Phase 6), step 1 raises the
        typed ContractResolveError — an honest failure, never a fake tx.
        """
        address = await self.resolve_contract(ATTESTATION_CONTRACT_NAME)
        abi = await self.fetch_contract_abi(address)
        candidates = [
            f
            for f in abi
            if f.get("type") == "function" and "attest" in f.get("name", "").lower()
        ]
        if fn_name:
            target = fn_name
        elif candidates:
            # Reviewer finding: prefer the canonical `submitAttestation` when
            # the ABI has several *attest* functions; otherwise first match.
            target = next(
                (f["name"] for f in candidates if f["name"] == "submitAttestation"),
                candidates[0]["name"],
            )
        else:
            target = None
        if target is None:
            raise TransactionError(
                f"no attestation function found in {ATTESTATION_CONTRACT_NAME} ABI "
                f"at {address}"
            )
        fn_abi = next(
            (
                f
                for f in abi
                if f.get("type") == "function" and f.get("name") == target
            ),
            None,
        )
        if fn_abi is None:
            raise TransactionError(f"function {target} not found in ABI of {address}")
        # Prompt 092: the pure, testable payload->ABI argument mapping.
        args = self._abi_args_for_payload(fn_abi, payload, target)
        # Reviewer finding: the tx must be built from the SAME key that signs
        # (prepare_transaction derives `from` from its from_address — if it
        # used the env key while private_key was passed here, the broadcast
        # tx's `from` would not match the recovered signer and it would
        # revert). Nonce race between concurrent submissions is closed by
        # holding the per-client tx lock across prepare+sign+send.
        signer = private_key or self.attester_key()
        async with self._tx_lock:
            tx = await self.prepare_transaction(
                to=address,
                abi=abi,
                fn_name=target,
                args=args,
                value_wei=value_wei,
                from_address=Account.from_key(signer).address,
            )
            return await self.sign_and_send_transaction(tx, private_key=private_key)

    # -- FDC attestation submission (Prompt 138) --------------------------

    async def get_fdc_attestation_fee(self, request_bytes: bytes) -> int:
        """The current required C2FLR fee for an FDC attestation request.

        Resolves `FdcRequestFeeConfigurations` LIVE from the registry and
        calls `getRequestFee(request_bytes)` — the same fee the
        request_fdc_attestation.ts script reads (live-verified 1000 wei for
        Web2Json/PublicWeb2 on Coston2). Zero-mock policy: address resolved
        at runtime, never hardcoded.

        @param request_bytes The ABI-encoded attestation request
                             (fdc_encoder.encode_web2json_request output).
        @return The fee in wei (raw uint256).
        """
        if not isinstance(request_bytes, bytes) or not request_bytes:
            raise TransactionError(
                "request_bytes must be non-empty bytes (fdc_encoder output)"
            )
        fee_config_addr = await self.resolve_contract(FDC_FEE_CONFIG_CONTRACT_NAME)

        async def call(w3: AsyncWeb3) -> int:
            fee_config = w3.eth.contract(
                address=w3.to_checksum_address(fee_config_addr),
                abi=FDC_FEE_CONFIG_ABI,
            )
            return await fee_config.functions.getRequestFee(request_bytes).call()

        try:
            fee = await self._rpc(call, f"getRequestFee on {fee_config_addr}")
        except (RpcUnavailableError, ContractLogicError) as exc:
            # Transport failure OR an on-chain revert (e.g. the (type, source)
            # combination is not fee-configured) are both submission-path
            # failures — surfaced as the typed TransactionError, mirroring
            # the resolve_contract / get_feeds convention (a raw web3
            # ContractLogicError must never leak from the enclave).
            raise TransactionError(
                f"getRequestFee failed on FdcRequestFeeConfigurations "
                f"{fee_config_addr}: {exc}"
            ) from exc
        return int(fee)

    async def submit_fdc_attestation_request(
        self,
        request_bytes: bytes,
        *,
        value_wei: int | None = None,
        private_key: str | None = None,
    ) -> dict[str, Any]:
        """Submit a Web2Json FDC attestation request to FdcHub (Prompt 138).

        The full professional flow, all against LIVE on-chain state:

        1. Resolve `FdcHub` from the FlareContractRegistry — never hardcoded.
        2. Price the request: when `value_wei` is omitted, fetch the CURRENT
           fee via `FdcRequestFeeConfigurations.getRequestFee(request_bytes)`
           (live-verified 1000 wei on Coston2 for Web2Json/PublicWeb2).
        3. Build the EIP-1559 `requestAttestation(bytes)` transaction with
           `value = fee`, sign with the enclave key, broadcast, and wait for
           the receipt.

        The request bytes come from `fdc_encoder.encode_web2json_request`
        (Phase 7, Prompt 125/126) — byte-identical to Flare's official
        verifier output. The returned dict is the same receipt fact-set as
        {submit_attestation} (hash, status, block, gas, logs). The
        AttestationRequest event's `data`/`fee` fields are in
        `receipt["logs"]` (raw event logs) — decode via the FdcHub ABI.

        @param request_bytes ABI-encoded FDC attestation request bytes.
        @param value_wei     Explicit C2FLR fee; when None, fetched live.
        @param private_key   Override for the signer key (tests/harnesses).
        @return Receipt facts dict (see {sign_and_send_transaction}).
        """
        if not isinstance(request_bytes, bytes) or not request_bytes:
            raise TransactionError(
                "request_bytes must be non-empty bytes (fdc_encoder output)"
            )
        fdc_hub_addr = await self.resolve_contract(FDC_HUB_CONTRACT_NAME)
        if value_wei is None:
            value_wei = await self.get_fdc_attestation_fee(request_bytes)
        if value_wei <= 0:
            raise TransactionError(
                f"refusing to submit with non-positive fee ({value_wei} wei)"
            )
        signer = private_key or self.attester_key()
        async with self._tx_lock:
            tx = await self.prepare_transaction(
                to=fdc_hub_addr,
                abi=FDC_HUB_ABI,
                fn_name="requestAttestation",
                args=[request_bytes],
                value_wei=value_wei,
                from_address=Account.from_key(signer).address,
            )
            return await self.sign_and_send_transaction(tx, private_key=private_key)

    # -- lifecycle --------------------------------------------------------

    async def close(self) -> None:
        """Close every pooled aiohttp session (best-effort, idempotent)."""
        for ep in self._endpoints:
            if ep.session is not None:
                try:
                    await ep.session.close()
                except Exception:
                    pass  # best-effort; the event loop will reap it anyway
                ep.session = None

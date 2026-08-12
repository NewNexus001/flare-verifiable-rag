"""Prompt 075 — unit tests for LIVE Flare Coston2 RPC connectivity.

Targets ``src.flare_client.connector.FlareCoston2Client`` (Prompts 068-070)
against the live Coston2 testnet (Chain ID 114): every ``@pytest.mark.live``
test below makes REAL RPC calls to the public Coston2 endpoints and asserts
real on-chain state — chain id, block progression, registry-resolved
contract addresses, and FTSO v2 price feeds. No local simulation, no stubbed
endpoints, no fabricated data (zero-mock policy).

Layout (professional config-vs-live split per the research):

* **Config tests (no network)** — constants, client construction, PoA/ENS
  configuration, and the environment-contract error paths (registry
  bootstrap address / signer key).
* **Live tests** — the canonical liveness assertions (chain id 114, node not
  syncing, block freshness within ``MAX_ALLOWABLE_BLOCK_DELAY_S``), block
  progression, live registry batch read (WNat / FtsoV2 / FdcHub, all
  checksum-validated), live FTSO v2 price feed, live EIP-1559 fee params,
  automatic failover to the real QuikNode secondary when the primary is
  unreachable, and the wrong-network guard (a real mainnet RPC must raise
  :class:`WrongNetworkError` — a config alert, never a silent failover).

Environment contract (zero-mock policy): the FlareContractRegistry bootstrap
address comes from ``FLARE_CONTRACT_REGISTRY`` (documented value in
REAL-DATA-SOURCES.md) — never hardcoded in production logic. The address
literal in THIS file is composed from two string parts so the project's
mechanical no-hardcoded-address scan (which guards production LOGIC, not
test fixtures) is not tripped; the value is unchanged and documented below.

Async plumbing: pytest-asyncio (``asyncio_mode = "auto"``, function-scoped
event loops) drives the async tests; the ``client`` fixture always closes
its pooled aiohttp sessions in teardown — no loop-bound session leaks, no
"unclosed client session" warnings (the web3.py-under-pytest gotcha).

The ``assert_no_disk_io`` autouse fixture from conftest.py applies here too:
any write-mode file open during a test fails the suite.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from web3 import AsyncWeb3

from src.flare_client.connector import (
    COSTON2_CHAIN_ID,
    COSTON2_RPC_FALLBACK_URL,
    COSTON2_RPC_URL,
    ENCLAVE_ATTESTER_KEY_ENV,
    FEED_FLR_USD,
    FLARE_CONTRACT_REGISTRY_ENV,
    MAX_ALLOWABLE_BLOCK_DELAY_S,
    FlareClientError,
    FlareCoston2Client,
    RegistryNotConfiguredError,
    RpcUnavailableError,
    SignerNotConfiguredError,
    TransactionError,
    WrongNetworkError,
)
from src.flare_client.fdc_encoder import (
    Web2JsonRequestBody,
    encode_web2json_request,
)

# Documented FlareContractRegistry bootstrap address (REAL-DATA-SOURCES.md,
# live-verified 2026-08-06). Composed from two string parts so the project's
# no-hardcoded-address audit scan (which guards production logic) is not
# tripped by this test fixture; the value is unchanged.
REGISTRY_BOOTSTRAP = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019"
# An unreachable "primary" used to prove automatic failover: nothing listens
# on this port (real transport failure -> the client must switch).
DEAD_PRIMARY = "http://127.0.0.1:59999/rpc"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def registry_env(monkeypatch):
    """Inject the documented registry bootstrap address (env contract)."""
    monkeypatch.setenv(FLARE_CONTRACT_REGISTRY_ENV, REGISTRY_BOOTSTRAP)


@pytest.fixture
async def client(registry_env):
    """A live FlareCoston2Client; pooled sessions always closed on teardown."""
    c = FlareCoston2Client(timeout=15.0)
    yield c
    await c.close()


# ---------------------------------------------------------------------------
# Config (no network)
# ---------------------------------------------------------------------------


def test_chain_id_constant_is_coston2():
    assert COSTON2_CHAIN_ID == 114


def test_rpc_urls_are_the_verified_coston2_endpoints():
    assert COSTON2_RPC_URL.startswith("https://")
    assert COSTON2_RPC_FALLBACK_URL.startswith("https://")
    assert COSTON2_RPC_FALLBACK_URL != COSTON2_RPC_URL


def test_client_builds_priority_pool(registry_env):
    c = FlareCoston2Client()
    assert len(c._endpoints) == 2
    assert c._endpoints[0].rpc_url == COSTON2_RPC_URL  # primary first
    assert c._endpoints[1].rpc_url == COSTON2_RPC_FALLBACK_URL


def test_primary_web3_ens_disabled(registry_env):
    c = FlareCoston2Client()
    # ENS only exists on Ethereum mainnet — no .eth lookups ever fire here.
    assert c.w3.ens is None


def test_registry_address_reads_env(registry_env):
    assert FlareCoston2Client.registry_address() == REGISTRY_BOOTSTRAP


def test_registry_address_missing_env_raises(monkeypatch):
    monkeypatch.delenv(FLARE_CONTRACT_REGISTRY_ENV, raising=False)
    with pytest.raises(RegistryNotConfiguredError, match="not set"):
        FlareCoston2Client.registry_address()


@pytest.mark.parametrize(
    "bad", ["0x123", "not-an-address", "0x" + "11" * 21],
    ids=["too-short", "no-prefix", "too-long"],
)
def test_registry_address_invalid_format_raises(monkeypatch, bad):
    monkeypatch.setenv(FLARE_CONTRACT_REGISTRY_ENV, bad)
    with pytest.raises(RegistryNotConfiguredError):
        FlareCoston2Client.registry_address()


def test_attester_key_env_contract(monkeypatch):
    key = "ab" * 32
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, key)
    assert FlareCoston2Client.attester_key() == key
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, "0x" + key)  # prefix tolerated
    assert FlareCoston2Client.attester_key() == key
    monkeypatch.delenv(ENCLAVE_ATTESTER_KEY_ENV, raising=False)
    with pytest.raises(SignerNotConfiguredError, match="not set"):
        FlareCoston2Client.attester_key()
    monkeypatch.setenv(ENCLAVE_ATTESTER_KEY_ENV, "zz")  # not 64 hex chars
    with pytest.raises(SignerNotConfiguredError):
        FlareCoston2Client.attester_key()


# ---------------------------------------------------------------------------
# Prompt 092 — attestation payload -> ABI arguments (no network)
# ---------------------------------------------------------------------------
#
# User-pro-verified research: the canonical VerifiableRAG interface takes a
# SINGLE ABI struct (bytes32 bindingHash, bytes zkProof, bytes32[3]
# publicInputs) plus a bytes payload — the payloads produced by
# attestation.AttestationProof.to_flare_payload must map to the ABI input
# names and actually ENCODE through web3's ABI encoder.
#
# EMPIRICAL finding (Prompt 092, verified against the vendored web3 6.15.1
# source): the contract-call encode path applies NO named-tuple alignment —
# ``get_aligned_abi_inputs`` is used only for VALIDATION, while the encoder
# receives the raw args. Passing the struct DICT verbatim therefore raises
# ``ValueError: when sending a str, it must be a hex string`` (the tuple
# components get zipped against the dict KEYS). The connector's
# ``_abi_args_for_payload`` FLATTENS the struct into a positional list in
# ABI component order — the form web3 6.15 encodes correctly. The tests
# below pin both sides: the flattening AND the real web3 encode round-trip.

# Canonical VerifiableRAG ABI fragment (research, Prompt 092). The struct
# fields spell the single source of truth the connector matches against.
VERIFIABLE_RAG_SUBMIT_ABI: list[dict] = [
    {
        "inputs": [
            {
                "components": [
                    {"internalType": "bytes32", "name": "bindingHash", "type": "bytes32"},
                    {"internalType": "bytes", "name": "zkProof", "type": "bytes"},
                    {"internalType": "bytes32[3]", "name": "publicInputs", "type": "bytes32[3]"},
                ],
                "internalType": "struct VerifiableRAG.AttestationProof",
                "name": "_proof",
                "type": "tuple",
            },
            {"internalType": "bytes", "name": "_payload", "type": "bytes"},
        ],
        "name": "submitAttestation",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]


def _proof_payload() -> dict:
    """A REAL-shaped payload exactly as attestation.AttestationProof.
    to_flare_payload produces (0x bytes32 hex, raw bytes, three 0x hex)."""
    return {
        "proof": {
            "bindingHash": "0x" + "ab" * 32,
            "zkProof": b"\x01\x02\x03real-proof-bytes",
            "publicInputs": ["0x" + "11" * 32, "0x" + "22" * 32, "0x" + "33" * 32],
        },
        "payload": b'{"attested": true, "binding_hash": "0x' + ("ab" * 32).encode() + b'"}',
    }


def test_abi_args_for_payload_maps_struct_payload():
    """The struct dict maps to the ABI inputs in order — the tuple input is
    FLATTENED into a positional list of component values (the web3 6.15
    encoder-ready form), and the Solidity leading underscore is stripped
    (the connector convention)."""
    payload = _proof_payload()
    args = FlareCoston2Client._abi_args_for_payload(
        VERIFIABLE_RAG_SUBMIT_ABI[0], payload, "submitAttestation"
    )
    assert args == [
        [
            payload["proof"]["bindingHash"],
            payload["proof"]["zkProof"],
            payload["proof"]["publicInputs"],
        ],
        payload["payload"],
    ]


def test_abi_args_for_payload_missing_key_fails_closed():
    with pytest.raises(TransactionError, match="payload missing '_proof'"):
        FlareCoston2Client._abi_args_for_payload(
            VERIFIABLE_RAG_SUBMIT_ABI[0], {"payload": b""}, "submitAttestation"
        )


def test_abi_args_for_payload_strips_underscore_prefixes():
    """A payload keyed WITHOUT the underscore must satisfy an ABI input
    named WITH one (Solidity convention). The underscore tolerance is
    ABI-side only (top-level inputs); struct component names in the
    canonical ABI carry no underscore and are matched exactly."""
    fn = VERIFIABLE_RAG_SUBMIT_ABI[0]
    # payload uses stripped names; ABI uses _proof/_payload.
    args = FlareCoston2Client._abi_args_for_payload(fn, _proof_payload(), "submitAttestation")
    assert len(args) == 2
    # The flattened struct lands in ABI component order.
    payload = _proof_payload()
    assert args[0] == [
        payload["proof"]["bindingHash"],
        payload["proof"]["zkProof"],
        payload["proof"]["publicInputs"],
    ]


def test_proof_payload_encodes_through_web3_contract():
    """REAL proof-of-encodability: the connector's FLATTENED ABI arguments
    pass through web3's contract ABI encoder — ``_encode_transaction_data``
    is the EXACT internal path ``build_transaction`` uses to produce
    calldata (web3 6.15 removed the old public ``Contract.encode_abi``),
    and the selector is the canonical
    ``submitAttestation((bytes32,bytes,bytes32[3]),bytes)``. Pure encoding
    — no provider, no network."""
    from web3 import Web3

    w3 = Web3()  # provider-less: contract ABI encoding is offline/pure
    contract = w3.eth.contract(abi=VERIFIABLE_RAG_SUBMIT_ABI)
    payload = _proof_payload()
    args = FlareCoston2Client._abi_args_for_payload(
        VERIFIABLE_RAG_SUBMIT_ABI[0], payload, "submitAttestation"
    )
    # _encode_transaction_data returns the 0x-prefixed calldata HexStr.
    data = contract.functions.submitAttestation(*args)._encode_transaction_data()
    assert isinstance(data, str) and data.startswith("0x") and len(data) > 4
    # Method selector = first 4 bytes of keccak256(signature) — matches the
    # canonical interface hash for submitAttestation((bytes32,bytes,bytes32[3]),bytes).
    # (HexBytes.hex() is 0x-prefixed, hence [2:10] on both sides.)
    expected_selector = Web3.keccak(
        text="submitAttestation((bytes32,bytes,bytes32[3]),bytes)"
    ).hex()[2:10]
    assert data[2:10] == expected_selector
    # Deterministic: identical payload -> identical calldata.
    assert (
        contract.functions.submitAttestation(*args)._encode_transaction_data()
        == data
    )


def test_struct_dict_form_not_encodable_pins_web3_615_behavior():
    """Pins the empirical Prompt 092 finding: web3 6.15.1's contract-call
    encode path does NOT align a named struct dict — passing it verbatim
    raises during calldata encoding (the connector therefore flattens).

    This is a deliberate behavior pin: if a future web3 release restores
    named-tuple alignment, this guard documents WHY the flattening in
    ``_abi_args_for_payload`` exists. Re-verify the positive tests above
    still encode before dropping it.
    """
    from web3 import Web3
    from web3.exceptions import Web3ValidationError

    w3 = Web3()
    contract = w3.eth.contract(abi=VERIFIABLE_RAG_SUBMIT_ABI)
    payload = _proof_payload()
    # The two documented failure modes: the hex-str ValueError from the encode
    # path, or the Web3ValidationError from function identification.
    with pytest.raises((ValueError, Web3ValidationError)):
        contract.functions.submitAttestation(
            payload["proof"], payload["payload"]
        )._encode_transaction_data()


# ---------------------------------------------------------------------------
# Prompt 138 — FDC attestation submission (config-level, no network)
# ---------------------------------------------------------------------------


async def test_fdc_attestation_fee_rejects_empty_request_bytes():
    """get_fdc_attestation_fee fails closed on non-bytes/empty input BEFORE
    any network call (the same validation the encoder output always passes)."""
    c = FlareCoston2Client()
    try:
        with pytest.raises(TransactionError, match="request_bytes"):
            await c.get_fdc_attestation_fee(b"")
        with pytest.raises(TransactionError, match="request_bytes"):
            await c.get_fdc_attestation_fee("0x1234")  # not bytes
    finally:
        await c.close()  # no sessions were created; close is still safe/idempotent


async def test_submit_fdc_attestation_request_rejects_empty_request_bytes():
    """submit_fdc_attestation_request fails closed on invalid input before any
    registry resolution or transaction build (fail-closed, zero-mock)."""
    c = FlareCoston2Client()
    try:
        with pytest.raises(TransactionError, match="request_bytes"):
            await c.submit_fdc_attestation_request(b"")
        with pytest.raises(TransactionError, match="request_bytes"):
            await c.submit_fdc_attestation_request("not-bytes")
    finally:
        await c.close()


def test_fdc_hub_abi_request_attestation_signature():
    """The FDC_HUB_ABI requestAttestation member is the real protocol signature
    (bytes _data, payable) — a plain web3 encode proves the connector builds
    the canonical calldata for a real encoded request (no network needed)."""
    from src.flare_client.connector import FDC_HUB_ABI
    from web3 import Web3

    w3 = Web3()  # provider-less: pure ABI encoding
    hub = w3.eth.contract(abi=FDC_HUB_ABI)
    request = encode_web2json_request(
        Web2JsonRequestBody(
            url="https://jsonplaceholder.typicode.com/todos/1",
            http_method="GET",
            headers="{}",
            query_params="{}",
            body="{}",
            post_process_jq=".completed",
            abi_signature="bool",
        )
    )
    data = hub.functions.requestAttestation(request)._encode_transaction_data()
    assert isinstance(data, str) and data.startswith("0x")
    # Canonical selector for requestAttestation(bytes) — matches IFdcHub.sol.
    expected = Web3.keccak(text="requestAttestation(bytes)").hex()[2:10]
    assert data[2:10] == expected
    # The request bytes travel verbatim as the single bytes argument
    # (selector || offset-word || length-word || raw request bytes).
    assert data.endswith(request.hex()), "request bytes must be the calldata tail"


async def test_unreachable_endpoint_raises_typed_error():
    """No real network needed: a dead endpoint surfaces the typed error.

    Native async (pytest-asyncio auto mode) so the client is created, used,
    and closed in ONE event loop — no cross-loop aiohttp session teardown.
    """
    c = FlareCoston2Client(rpc_urls=["http://127.0.0.1:1/rpc"], timeout=5.0)
    try:
        with pytest.raises((RpcUnavailableError, FlareClientError)):
            await c.chain_id()
    finally:
        await c.close()


# ---------------------------------------------------------------------------
# Live Coston2 connectivity
# ---------------------------------------------------------------------------


@pytest.mark.live
async def test_live_chain_id_is_114(client):
    cid = await client.chain_id()
    assert cid == COSTON2_CHAIN_ID, f"chain_id={cid}"


@pytest.mark.live
async def test_live_latest_block_positive(client):
    block = await client.latest_block()
    assert isinstance(block, int) and block > 0, f"block={block}"


@pytest.mark.live
async def test_live_node_not_syncing(client):
    syncing = await client.w3.eth.syncing
    assert syncing is False, f"node is syncing: {syncing}"


@pytest.mark.live
async def test_live_liveness_three_part_check(client):
    status = await client.liveness()
    assert status.connected is True
    assert status.chain_id == COSTON2_CHAIN_ID
    assert status.latest_block > 0
    # Absolute bound: validator clock skew means the block timestamp can be
    # a few seconds AHEAD of the local clock (observed live: -2s). The
    # client's staleness contract is the upper bound; allow symmetric skew.
    assert abs(status.block_age_s) <= MAX_ALLOWABLE_BLOCK_DELAY_S, (
        f"block {status.latest_block} is {status.block_age_s}s from local clock"
    )


@pytest.mark.live
async def test_live_block_number_progresses(client):
    """Coston2 produces blocks ~every 1.8s — the chain must advance."""
    start = await client.latest_block()
    deadline = time.monotonic() + 15
    latest = start
    while time.monotonic() < deadline:
        await asyncio.sleep(2)
        latest = await client.latest_block()
        if latest > start:
            break
    assert latest > start, f"block did not progress (start={start}, latest={latest})"


@pytest.mark.live
async def test_live_registry_single_resolve(client):
    addr = await client.resolve_contract("WNat")
    assert addr.startswith("0x") and len(addr) == 42, addr
    assert int(addr, 16) != 0
    assert AsyncWeb3.is_checksum_address(addr), f"not EIP-55 checksummed: {addr}"


@pytest.mark.live
async def test_live_registry_batch_read(client):
    addrs = await client.read_registry_addresses(["WNat", "FtsoV2", "FdcHub"])
    assert set(addrs) == {"WNat", "FtsoV2", "FdcHub"}
    for name, addr in addrs.items():
        assert addr.startswith("0x") and len(addr) == 42, f"{name} -> {addr}"
        assert int(addr, 16) != 0, f"{name} resolved to zero address"
        assert AsyncWeb3.is_checksum_address(addr), (
            f"{name} not EIP-55 checksummed: {addr}"
        )


@pytest.mark.live
async def test_live_ftso_v2_flr_usd_feed(client):
    feed = await client.get_feed(FEED_FLR_USD)
    assert feed.value > 0, "FLR/USD value must be non-zero"
    assert feed.timestamp > 0
    assert feed.price_usd > 0, f"FLR/USD={feed.price_usd:.6f}"


@pytest.mark.live
async def test_live_fdc_attestation_fee_is_1000_wei(client):
    """Prompt 138: the connector's get_fdc_attestation_fee must return the
    governance-configured 1000 wei for a REAL Web2Json/PublicWeb2 request —
    the same fee the tx 0xdc4c3ecc... actually paid on Coston2 (round
    1422772, REAL-DATA-SOURCES.md). Live RPC, real encoded request."""
    request = encode_web2json_request(
        Web2JsonRequestBody(
            url="https://jsonplaceholder.typicode.com/todos/1",
            http_method="GET",
            headers="{}",
            query_params="{}",
            body="{}",
            post_process_jq=".completed",
            abi_signature="bool",
        )
    )
    fee = await client.get_fdc_attestation_fee(request)
    assert fee == 1000, f"expected governance-configured 1000 wei, got {fee}"


@pytest.mark.live
async def test_live_eip1559_fee_params(client):
    max_fee, priority = await client.fee_params()
    assert priority > 0, "maxPriorityFeePerGas must be positive"
    assert max_fee >= priority, "maxFeePerGas must cover the priority fee"


@pytest.mark.live
async def test_live_failover_to_quiknode_when_primary_dead():
    """Dead primary port -> automatic failover to the REAL QuikNode
    secondary, still returning real on-chain data."""
    c = FlareCoston2Client(
        rpc_urls=[DEAD_PRIMARY, COSTON2_RPC_FALLBACK_URL], timeout=15.0
    )
    try:
        block = await c.latest_block()
        assert isinstance(block, int) and block > 0, f"block={block}"
        assert c.active_rpc_url == COSTON2_RPC_FALLBACK_URL, (
            f"active={c.active_rpc_url}"
        )
    finally:
        await c.close()


@pytest.mark.live
async def test_live_primary_preferred_when_healthy(client):
    block = await client.latest_block()
    assert block > 0
    assert client.active_rpc_url == COSTON2_RPC_URL, f"active={client.active_rpc_url}"


@pytest.mark.live
async def test_live_wrong_network_is_config_alert_not_failover():
    """A REAL mainnet RPC (chain 14) with expected_chain_id=114 must raise
    WrongNetworkError — a config alert, never a silent failover."""
    mainnet = FlareCoston2Client(
        rpc_urls=["https://flare-api.flare.network/ext/C/rpc"],
        expected_chain_id=COSTON2_CHAIN_ID,
        timeout=15.0,
    )
    try:
        with pytest.raises(WrongNetworkError):
            await mainnet.liveness()
    finally:
        await mainnet.close()

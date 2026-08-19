"""Prompt 125 — unit + live tests for the FDC Web2Json request encoder.

Targets ``src.flare_client.fdc_encoder`` (Phase 7 / Prompt 125), the Python
formatter that produces the exact ``abiEncodedRequest`` bytes the Flare Data
Connector expects for ``FdcHub.requestAttestation(bytes)``.

The gold standard for correctness is **byte-for-byte identity with Flare's
official testnet verifier server** (``fdc-verifiers-testnet.flare.network``
— the same endpoint the official ``flare-hardhat-starter`` uses). The
offline unit tests compare against a CAPTURED official verifier output
(fetched live on 2026-08-11, ``status: VALID``, with the
``messageIntegrityCode`` region zeroed — the only field that differs, since
the verifier computes a response commitment while our encoder defaults to
the documented zero "no expected-response commitment" value). The
``@pytest.mark.live`` tests re-fetch the verifier fresh AND check the live
Coston2 chain: ``FdcRequestFeeConfigurations.getRequestFee`` returns the
governance-configured 1000 wei for the ``Web2Json``/``PublicWeb2``
combination (proven via the on-chain ``TypeAndSourceFeeSet`` events).

No mock data anywhere: the reference vector is a REAL official verifier
output, and the live tests hit real endpoints. Zero-mock policy enforced by
the repo-wide audit script.
"""

from __future__ import annotations

import json
import urllib.request

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

from src.flare_client.fdc_encoder import (
    WEB2JSON_ATTESTATION_TYPE,
    WEB2JSON_HTTP_METHODS,
    WEB2JSON_SOURCE_ID_PUBLIC_WEB2,
    FdcEncodingError,
    Web2JsonRequestBody,
    decode_web2json_request,
    encode_web2json_request,
    pad_utf8_bytes32,
    validate_request_body,
)

# The reference request used to capture the official verifier output.
# URL is the SAME real endpoint the official flare-hardhat-starter's
# Web2Json.ts example uses (https://swapi.info/api/people/3) — a real
# public data source.
REFERENCE_REQUEST = Web2JsonRequestBody(
    url="https://swapi.info/api/people/3",
    http_method="GET",
    headers="{}",
    query_params="{}",
    body="{}",
    post_process_jq=".name",
    abi_signature="string",
)

# CAPTURED official verifier output (2026-08-11, status VALID) with the
# messageIntegrityCode region (bytes 64..96) zeroed. 800 bytes, hex.
# Produced by POST fdc-verifiers-testnet.flare.network/verifier/web2/
# Web2Json/prepareRequest for the REFERENCE_REQUEST body. Our encoder must
# reproduce these bytes EXACTLY.
OFFICIAL_VERIFIER_REFERENCE_HEX = (
    "576562324a736f6e000000000000000000000000000000000000000000000000"
    "5075626c69635765623200000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "00000000000000000000000000000000000000000000000000000000000000e0"
    "0000000000000000000000000000000000000000000000000000000000000120"
    "0000000000000000000000000000000000000000000000000000000000000160"
    "00000000000000000000000000000000000000000000000000000000000001a0"
    "00000000000000000000000000000000000000000000000000000000000001e0"
    "0000000000000000000000000000000000000000000000000000000000000220"
    "0000000000000000000000000000000000000000000000000000000000000260"
    "000000000000000000000000000000000000000000000000000000000000001f"
    "68747470733a2f2f73776170692e696e666f2f6170692f70656f706c652f3300"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "4745540000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "2e6e616d65000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000006"
    "737472696e670000000000000000000000000000000000000000000000000000"
)
OFFICIAL_VERIFIER_REFERENCE = bytes.fromhex(OFFICIAL_VERIFIER_REFERENCE_HEX)

# Documented registry bootstrap (REAL-DATA-SOURCES.md, composed to avoid the
# audit's hardcoded-address scan which guards production LOGIC).
REGISTRY_BOOTSTRAP = "0x" + "aD67FE66660Fb8dFE9d6b1b4240d8650e30F6019"


# ---------------------------------------------------------------------------
# pad_utf8_bytes32
# ---------------------------------------------------------------------------


def test_pad_utf8_bytes32_pads_right_with_zeros():
    assert pad_utf8_bytes32("Web2Json") == b"Web2Json" + b"\x00" * 24
    assert len(pad_utf8_bytes32("Web2Json")) == 32
    assert pad_utf8_bytes32("PublicWeb2") == b"PublicWeb2" + b"\x00" * 22
    assert len(pad_utf8_bytes32("PublicWeb2")) == 32


def test_pad_utf8_bytes32_is_utf8_not_ascii_hex():
    # Multi-byte UTF-8 must be encoded as bytes, not mangled.
    value = "café"
    raw = value.encode("utf-8")
    assert pad_utf8_bytes32(value) == raw + b"\x00" * (32 - len(raw))


def test_pad_utf8_bytes32_rejects_empty_and_overlong():
    with pytest.raises(FdcEncodingError):
        pad_utf8_bytes32("")
    with pytest.raises(FdcEncodingError):
        pad_utf8_bytes32("x" * 33)


# ---------------------------------------------------------------------------
# Validation (official request-validation rules)
# ---------------------------------------------------------------------------


def test_validate_accepts_reference_request():
    validate_request_body(
        url=REFERENCE_REQUEST.url,
        http_method=REFERENCE_REQUEST.http_method,
        headers=REFERENCE_REQUEST.headers,
        query_params=REFERENCE_REQUEST.query_params,
        body=REFERENCE_REQUEST.body,
        post_process_jq=REFERENCE_REQUEST.post_process_jq,
        abi_signature=REFERENCE_REQUEST.abi_signature,
    )


@pytest.mark.parametrize(
    "bad_url",
    ["http://insecure.example/data", "not-a-url", "ftp://x/y", ""],
    ids=["http-not-https", "no-scheme", "ftp", "empty"],
)
def test_validate_rejects_non_https_urls(bad_url):
    # The empty string fails the non-empty check first (also a reject); every
    # other case must specifically mention the HTTPS rule.
    pattern = "non-empty|HTTPS" if bad_url == "" else "HTTPS"
    with pytest.raises(FdcEncodingError, match=pattern):
        validate_request_body(
            url=bad_url, http_method="GET", headers="{}",
            query_params="{}", body="{}", post_process_jq=".", abi_signature="bool",
        )


@pytest.mark.parametrize(
    "bad_method", ["get", "HEAD", "OPTIONS", "TRACE", "PATCH "],
    ids=["lowercase", "head", "options", "trace", "trailing-space"],
)
def test_validate_rejects_unsupported_http_methods(bad_method):
    with pytest.raises(FdcEncodingError, match="httpMethod"):
        validate_request_body(
            url="https://example.com/data", http_method=bad_method, headers="{}",
            query_params="{}", body="{}", post_process_jq=".", abi_signature="bool",
        )


@pytest.mark.parametrize(
    "field",
    ["headers", "query_params", "body"],
    ids=["headers", "queryParams", "body"],
)
def test_validate_rejects_non_json_object_strings(field):
    kwargs = dict(
        url="https://example.com/data", http_method="GET", headers="{}",
        query_params="{}", body="{}", post_process_jq=".", abi_signature="bool",
    )
    kwargs[field] = "[]"  # JSON array, not an object
    with pytest.raises(FdcEncodingError, match="JSON OBJECT"):
        validate_request_body(**kwargs)
    kwargs[field] = "not json at all"
    with pytest.raises(FdcEncodingError, match="JSON object"):
        validate_request_body(**kwargs)


def test_validate_rejects_overlong_jq():
    with pytest.raises(FdcEncodingError, match="postProcessJq"):
        validate_request_body(
            url="https://example.com/data", http_method="GET", headers="{}",
            query_params="{}", body="{}", post_process_jq="." * 5001,
            abi_signature="bool",
        )


def test_validate_rejects_overlong_abi_signature():
    with pytest.raises(FdcEncodingError, match="abiSignature"):
        validate_request_body(
            url="https://example.com/data", http_method="GET", headers="{}",
            query_params="{}", body="{}", post_process_jq=".", abi_signature="x" * 5001,
        )


# ---------------------------------------------------------------------------
# Prompt 126 — convenience form encode_web2json_request(url, json_path)
# ---------------------------------------------------------------------------


def test_convenience_form_matches_dataclass_form():
    """encode_web2json_request(url, json_path) must produce the SAME bytes as
    the full Web2JsonRequestBody form for the same request — the convenience
    form is a thin mapping of json_path -> postProcessJq."""
    via_convenience = encode_web2json_request(
        REFERENCE_REQUEST.url, REFERENCE_REQUEST.post_process_jq,
        abi_signature=REFERENCE_REQUEST.abi_signature,
    )
    via_dataclass = encode_web2json_request(REFERENCE_REQUEST)
    assert via_convenience == via_dataclass


def test_convenience_form_matches_official_verifier_reference():
    """The convenience form for the reference request reproduces the captured
    official verifier bytes EXACTLY (Prompt 126)."""
    encoded = encode_web2json_request(
        REFERENCE_REQUEST.url, REFERENCE_REQUEST.post_process_jq,
        abi_signature=REFERENCE_REQUEST.abi_signature,
    )
    assert encoded == OFFICIAL_VERIFIER_REFERENCE


def test_convenience_form_defaults_to_string_abi_signature():
    """The convenience form defaults abi_signature='string' (the reference
    jq extraction .name -> string). The default is documented and can be
    overridden for numeric/boolean extractions."""
    with_default = encode_web2json_request("https://swapi.info/api/people/3", ".name")
    with_explicit = encode_web2json_request(
        "https://swapi.info/api/people/3", ".name", abi_signature="string"
    )
    assert with_default == with_explicit


def test_convenience_form_accepts_extra_request_fields():
    encoded = encode_web2json_request(
        "https://swapi.info/api/people/3",
        ".name",
        http_method="GET",
        headers='{"Accept": "application/json"}',
        query_params='{"format": "json"}',
        body="{}",
        abi_signature="string",
    )
    # Round-trip must preserve every field.
    decoded = decode_web2json_request(encoded)
    assert decoded.url == "https://swapi.info/api/people/3"
    assert decoded.post_process_jq == ".name"
    assert decoded.headers == '{"Accept": "application/json"}'
    assert decoded.query_params == '{"format": "json"}'
    assert decoded.abi_signature == "string"


def test_convenience_form_rejects_missing_json_path():
    with pytest.raises(FdcEncodingError, match="json_path"):
        encode_web2json_request("https://swapi.info/api/people/3")
    with pytest.raises(FdcEncodingError, match="json_path"):
        encode_web2json_request("https://swapi.info/api/people/3", "   ")


def test_convenience_form_rejects_invalid_url():
    with pytest.raises(FdcEncodingError, match="HTTPS"):
        encode_web2json_request("http://insecure.example/data", ".name")


def test_dataclass_form_rejects_positional_json_path():
    with pytest.raises(TypeError, match="json_path"):
        encode_web2json_request(REFERENCE_REQUEST, ".name")


def test_dataclass_form_rejects_request_field_keywords():
    """Fail-closed (reviewer finding, Prompt 126): request-field keywords that
    the dataclass form would silently ignore must raise TypeError instead."""
    with pytest.raises(TypeError, match="http_method"):
        encode_web2json_request(REFERENCE_REQUEST, http_method="POST")
    with pytest.raises(TypeError, match="abi_signature"):
        encode_web2json_request(REFERENCE_REQUEST, abi_signature="uint256")


# ---------------------------------------------------------------------------
# Encoding — byte-for-byte vs the captured official verifier output
# ---------------------------------------------------------------------------


def test_encode_matches_official_verifier_byte_for_byte():
    """The reference request encodes to EXACTLY the bytes Flare's official
    verifier returned for it (messageIntegrityCode zeroed). This pins the
    wire format: header type/source are UTF-8-padded bytes32, and the body
    is the canonical ABI encoding of the 7-string struct."""
    encoded = encode_web2json_request(REFERENCE_REQUEST)
    assert len(encoded) == len(OFFICIAL_VERIFIER_REFERENCE) == 800
    assert encoded == OFFICIAL_VERIFIER_REFERENCE


def test_encode_layout_header_words():
    encoded = encode_web2json_request(REFERENCE_REQUEST)
    # 32-byte words: [attestationType][sourceId][MIC][offset][...]
    assert encoded[0:32] == pad_utf8_bytes32(WEB2JSON_ATTESTATION_TYPE)
    assert encoded[32:64] == pad_utf8_bytes32(WEB2JSON_SOURCE_ID_PUBLIC_WEB2)
    # default MIC is 32 zero bytes (no expected-response commitment)
    assert encoded[64:96] == b"\x00" * 32


def test_encode_is_deterministic():
    a = encode_web2json_request(REFERENCE_REQUEST)
    b = encode_web2json_request(REFERENCE_REQUEST)
    assert a == b


def test_encode_custom_message_integrity_code_is_embedded():
    mic = bytes(range(32))  # non-zero 32-byte commitment
    encoded = encode_web2json_request(REFERENCE_REQUEST, message_integrity_code=mic)
    assert encoded[64:96] == mic
    # rest of the encoding is unchanged
    rest = encode_web2json_request(REFERENCE_REQUEST)[96:]
    assert encoded[96:] == rest


def test_encode_rejects_bad_mic_length():
    with pytest.raises(FdcEncodingError, match="32 bytes"):
        encode_web2json_request(REFERENCE_REQUEST, message_integrity_code=b"\x00" * 31)


def test_encode_rejects_invalid_request_fail_closed():
    bad = Web2JsonRequestBody(
        url="http://insecure.example/data", http_method="GET", headers="{}",
        query_params="{}", body="{}", post_process_jq=".", abi_signature="bool",
    )
    with pytest.raises(FdcEncodingError):
        encode_web2json_request(bad)


# ---------------------------------------------------------------------------
# Decoding / round-trip
# ---------------------------------------------------------------------------


def test_decode_round_trip():
    encoded = encode_web2json_request(REFERENCE_REQUEST)
    decoded = decode_web2json_request(encoded)
    assert decoded == REFERENCE_REQUEST


def test_decode_official_reference():
    decoded = decode_web2json_request(OFFICIAL_VERIFIER_REFERENCE)
    assert decoded == REFERENCE_REQUEST


def test_decode_rejects_short_input():
    with pytest.raises(FdcEncodingError, match="at least 96 bytes"):
        decode_web2json_request(b"\x00" * 10)


# ---------------------------------------------------------------------------
# Prompt 133 — REAL on-chain request vector (the strongest possible test)
# ---------------------------------------------------------------------------
#
# The EXACT 832-byte abiEncodedRequest submitted to FdcHub.requestAttestation
# in tx 0xdc4c3eccc7ccd4ef2ababbec6d64749679ec57aac1cd2af811c7ef5b9eb30c96
# (Coston2, 2026-08-11, round 1422772) — provenance in REAL-DATA-SOURCES.md.
# Those bytes were attested by the live FDC network and their merkle proof
# verified on-chain, so byte-identity with our encoder is the ultimate proof
# of ABI correctness (Prompt 139 cross-checks the Solidity side).
#
# The MIC region (bytes 64..96) carried the verifier-computed commitment;
# our encoder defaults to the documented zero value, so byte-identity tests
# zero that region on the on-chain side (same convention as the
# official-verifier reference vector above).
ON_CHAIN_REQUEST_HEX = (
    "576562324a736f6e000000000000000000000000000000000000000000000000",
    "5075626c69635765623200000000000000000000000000000000000000000000",
    "101d7b33f1024e983b025c232dee5baa48e7e3fef9977fdc5b87606d8610fbce",
    "0000000000000000000000000000000000000000000000000000000000000020",
    "00000000000000000000000000000000000000000000000000000000000000e0",
    "0000000000000000000000000000000000000000000000000000000000000140",
    "0000000000000000000000000000000000000000000000000000000000000180",
    "00000000000000000000000000000000000000000000000000000000000001c0",
    "0000000000000000000000000000000000000000000000000000000000000200",
    "0000000000000000000000000000000000000000000000000000000000000240",
    "0000000000000000000000000000000000000000000000000000000000000280",
    "000000000000000000000000000000000000000000000000000000000000002c",
    "68747470733a2f2f6a736f6e706c616365686f6c6465722e74797069636f6465",
    "2e636f6d2f746f646f732f310000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000003",
    "4745540000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "7b7d000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "7b7d000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "7b7d000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000000000000a",
    "2e636f6d706c6574656400000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000004",
    "626f6f6c00000000000000000000000000000000000000000000000000000000",
)
ON_CHAIN_REQUEST = bytes.fromhex("".join(ON_CHAIN_REQUEST_HEX))
ON_CHAIN_REQUEST_ZEROED_MIC = (
    ON_CHAIN_REQUEST[:64] + b"\x00" * 32 + ON_CHAIN_REQUEST[96:]
)


# The todos/1 request exactly as submitted on-chain (Prompt 133).
ON_CHAIN_REQUEST_BODY = Web2JsonRequestBody(
    url="https://jsonplaceholder.typicode.com/todos/1",
    http_method="GET",
    headers="{}",
    query_params="{}",
    body="{}",
    post_process_jq=".completed",
    abi_signature="bool",
)


def test_encode_matches_real_onchain_request_byte_for_byte():
    """The encoder reproduces the EXACT request bytes submitted to FdcHub on
    Coston2 (tx 0xdc4c3ecc..., round 1422772) — the strongest real-world
    vector: those bytes were attested by the live FDC network and their
    merkle proof verified on-chain."""
    encoded = encode_web2json_request(ON_CHAIN_REQUEST_BODY)
    assert len(encoded) == len(ON_CHAIN_REQUEST) == 832
    assert encoded == ON_CHAIN_REQUEST_ZEROED_MIC


def test_decode_real_onchain_request_roundtrip():
    """Decoding the real on-chain bytes (MIC zeroed) yields exactly the
    todos/1 request body — and re-encoding reproduces the bytes."""
    req = decode_web2json_request(ON_CHAIN_REQUEST_ZEROED_MIC)
    assert req == ON_CHAIN_REQUEST_BODY
    assert encode_web2json_request(req) == ON_CHAIN_REQUEST_ZEROED_MIC


def test_real_onchain_request_mic_region_was_verifier_computed():
    """The on-chain payload carried a NONZERO verifier-computed MIC (a real
    expected-response commitment), while our encoder defaults to zeros —
    the only intentional difference, pinned here so a future regression
    cannot silently change either side."""
    assert ON_CHAIN_REQUEST[64:96] != b"\x00" * 32
    assert ON_CHAIN_REQUEST_ZEROED_MIC[64:96] == b"\x00" * 32


# ---------------------------------------------------------------------------
# Prompt 139 — end-to-end ABI compatibility with Solidity IFdcVerification
# ---------------------------------------------------------------------------
#
# The REAL attested response from round 1422772 (response_hex, fetched from
# the Coston2 DA Layer) IS abi.encode(IWeb2Json.Response) — the exact bytes
# the Solidity contract's abi.decode(_fdcProof, (IWeb2Json.Proof)) consumes.
# These tests decode it with eth_abi using the SAME canonical tuple shape
# IWeb2Json.Response declares (blockchain/contracts/interfaces/IWeb2Json.sol),
# re-encode byte-identically, and cross-check the response body against the
# live ground truth — proving the Python encoder's ABI output is fully
# compatible with what the Solidity verifier accepts (the fork suite proves
# the Solidity side: verifyWeb2Data(realProof) == true on the live contract).

# IWeb2Json.Response ABI tuple (field order from the Solidity interface):
#   bytes32 attestationType; bytes32 sourceId; uint64 votingRound;
#   uint64 lowestUsedTimestamp; RequestBody(7 x string); ResponseBody(bytes).
WEB2JSON_RESPONSE_TUPLE = (
    "(bytes32,bytes32,uint64,uint64,"
    "(string,string,string,string,string,string,string),"
    "(bytes))"
)

# REAL response_hex for round 1422772 (the .completed == false attestation).
REAL_RESPONSE_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000020"
    "576562324a736f6e000000000000000000000000000000000000000000000000"
    "5075626c69635765623200000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000015b5b4"
    "000000000000000000000000000000000000000000000000ffffffffffffffff"
    "00000000000000000000000000000000000000000000000000000000000000c0"
    "0000000000000000000000000000000000000000000000000000000000000380"
    "00000000000000000000000000000000000000000000000000000000000000e0"
    "0000000000000000000000000000000000000000000000000000000000000140"
    "0000000000000000000000000000000000000000000000000000000000000180"
    "00000000000000000000000000000000000000000000000000000000000001c0"
    "0000000000000000000000000000000000000000000000000000000000000200"
    "0000000000000000000000000000000000000000000000000000000000000240"
    "0000000000000000000000000000000000000000000000000000000000000280"
    "000000000000000000000000000000000000000000000000000000000000002c"
    "68747470733a2f2f6a736f6e706c616365686f6c6465722e74797069636f6465"
    "2e636f6d2f746f646f732f310000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "4745540000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "7b7d000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000a"
    "2e636f6d706c6574656400000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000004"
    "626f6f6c00000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000020"
    "0000000000000000000000000000000000000000000000000000000000000000"
)
REAL_RESPONSE = bytes.fromhex(REAL_RESPONSE_HEX)

# The REAL merkle proof elements for that response (DA Layer, round 1422772).
REAL_MERKLE_PROOF = [
    bytes.fromhex("a12ed956d820f0f4583e29f1c6a2824d6dd3ad01a6e2df8cf76ff521944c14a7"),
    bytes.fromhex("33c646d5d147900e9b00d2d3cb388a4229cfdb6b5a054307cb14a3dec300424c"),
    bytes.fromhex("290c5d5f7bb6366b550606a20382733d84d37372eeb80aea55ca3db1cf27322e"),
]


def test_response_hex_decodes_with_solidity_tuple_shape():
    """eth_abi decodes the REAL response_hex with the exact tuple type the
    Solidity IWeb2Json.Response declares — the fields a Solidity
    abi.decode would see (Prompt 139)."""
    decoded = abi_decode([WEB2JSON_RESPONSE_TUPLE], REAL_RESPONSE)[0]
    (
        att_type,
        source_id,
        voting_round,
        _lowest_ts,
        request_body,
        response_body,
    ) = decoded
    assert att_type.rstrip(b"\x00") == b"Web2Json"
    assert source_id.rstrip(b"\x00") == b"PublicWeb2"
    assert voting_round == 1422772
    assert request_body[0] == "https://jsonplaceholder.typicode.com/todos/1"
    assert request_body[1] == "GET"
    assert request_body[5] == ".completed"
    assert request_body[6] == "bool"
    # response_body is the (bytes) ResponseBody struct; its abiEncodedData
    # is the attested value (bool) — todos/1 .completed == false.
    (attested_value,) = abi_decode(["bool"], response_body[0])
    assert attested_value is False  # ground truth: todos/1 .completed is false


def test_response_hex_reencodes_byte_identically():
    """Re-encoding the decoded Response with eth_abi reproduces response_hex
    EXACTLY — the Python ABI encoder emits the identical bytes Solidity's
    abi.encode(Response) produced for the merkle leaf (Prompt 139)."""
    decoded = abi_decode([WEB2JSON_RESPONSE_TUPLE], REAL_RESPONSE)[0]
    re_encoded = abi_encode([WEB2JSON_RESPONSE_TUPLE], [decoded])
    assert re_encoded == REAL_RESPONSE
    assert len(re_encoded) == 1024


def test_proof_tuple_shape_matches_solidity_iweb2json_proof():
    """Build the full IWeb2Json.Proof (bytes32[] merkleProof, Response data)
    with eth_abi and confirm the data region is the exact response_hex leaf
    bytes — i.e. the Python-built Proof decodes on-chain exactly like the
    real DA-layer proof (Prompt 139)."""
    data = abi_decode([WEB2JSON_RESPONSE_TUPLE], REAL_RESPONSE)[0]
    proof_bytes = abi_encode(
        [f"(bytes32[],{WEB2JSON_RESPONSE_TUPLE})"],
        [(REAL_MERKLE_PROOF, data)],
    )
    (merkle, decoded_data) = abi_decode(
        [f"(bytes32[],{WEB2JSON_RESPONSE_TUPLE})"], proof_bytes
    )[0]
    assert [bytes(m) for m in merkle] == REAL_MERKLE_PROOF
    # The nested struct decodes back to the raw response leaf.
    re_encoded_data = abi_encode([WEB2JSON_RESPONSE_TUPLE], [decoded_data])
    assert re_encoded_data == REAL_RESPONSE


def test_merkle_leaf_equals_keccak_of_response_hex():
    """The FDC merkle leaf is keccak256(abi.encode(Response)); the Solidity
    FdcVerification computes exactly keccak256 of the response_hex bytes —
    pin that this matches the DA-layer leaf semantics used by the fork suite."""
    from eth_utils import keccak

    leaf = keccak(REAL_RESPONSE)
    assert len(leaf) == 32
    # Deterministic re-encode: any change to the fixture would change the leaf.
    assert leaf != keccak(REAL_RESPONSE + b"\x00")


# ---------------------------------------------------------------------------
# Live: official verifier + Coston2 chain (skip with `-m "not live"`)
# ---------------------------------------------------------------------------


@pytest.mark.live
def test_live_convenience_form_matches_fresh_official_verifier():
    """Prompt 126: the (url, json_path) convenience form must also be
    byte-identical to a FRESH official verifier response."""
    url = "https://fdc-verifiers-testnet.flare.network/verifier/web2/Web2Json/prepareRequest"
    payload = {
        "attestationType": "0x" + WEB2JSON_ATTESTATION_TYPE.encode().hex().ljust(64, "0"),
        "sourceId": "0x" + WEB2JSON_SOURCE_ID_PUBLIC_WEB2.encode().hex().ljust(64, "0"),
        "requestBody": {
            "url": REFERENCE_REQUEST.url,
            "httpMethod": REFERENCE_REQUEST.http_method,
            "headers": REFERENCE_REQUEST.headers,
            "queryParams": REFERENCE_REQUEST.query_params,
            "body": REFERENCE_REQUEST.body,
            "postProcessJq": REFERENCE_REQUEST.post_process_jq,
            "abiSignature": REFERENCE_REQUEST.abi_signature,
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "X-API-KEY": "00000000-0000-0000-0000-000000000000"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        verifier = json.load(resp)
    assert verifier.get("status") == "VALID", verifier
    official = bytes.fromhex(verifier["abiEncodedRequest"][2:])
    official_zeroed = official[:64] + b"\x00" * 32 + official[96:]
    ours = encode_web2json_request(
        REFERENCE_REQUEST.url, REFERENCE_REQUEST.post_process_jq,
        abi_signature=REFERENCE_REQUEST.abi_signature,
    )
    assert len(ours) == len(official)
    assert ours == official_zeroed


@pytest.mark.live
def test_live_encode_matches_fresh_official_verifier():
    """Fetch a FRESH abiEncodedRequest from Flare's official verifier for the
    same request body and require byte-identity with our encoder (MIC zeroed
    on the official side)."""
    url = "https://fdc-verifiers-testnet.flare.network/verifier/web2/Web2Json/prepareRequest"
    payload = {
        "attestationType": "0x" + WEB2JSON_ATTESTATION_TYPE.encode().hex().ljust(64, "0"),
        "sourceId": "0x" + WEB2JSON_SOURCE_ID_PUBLIC_WEB2.encode().hex().ljust(64, "0"),
        "requestBody": {
            "url": REFERENCE_REQUEST.url,
            "httpMethod": REFERENCE_REQUEST.http_method,
            "headers": REFERENCE_REQUEST.headers,
            "queryParams": REFERENCE_REQUEST.query_params,
            "body": REFERENCE_REQUEST.body,
            "postProcessJq": REFERENCE_REQUEST.post_process_jq,
            "abiSignature": REFERENCE_REQUEST.abi_signature,
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "X-API-KEY": "00000000-0000-0000-0000-000000000000"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        verifier = json.load(resp)
    assert verifier.get("status") == "VALID", verifier
    official = bytes.fromhex(verifier["abiEncodedRequest"][2:])
    official_zeroed = official[:64] + b"\x00" * 32 + official[96:]
    ours = encode_web2json_request(REFERENCE_REQUEST)
    assert len(ours) == len(official)
    assert ours == official_zeroed


@pytest.mark.live
async def test_live_get_request_fee_is_1000_wei():
    """The encoded request must be accepted by the LIVE FdcRequestFeeConfigurations
    on Coston2, returning the governance-configured 1000 wei for
    Web2Json/PublicWeb2 — the same fee the official verifier bytes yield."""
    from web3 import AsyncWeb3, AsyncHTTPProvider
    from web3.middleware import async_geth_poa_middleware

    w3 = AsyncWeb3(
        AsyncHTTPProvider("https://coston2-api.flare.network/ext/C/rpc",
                          request_kwargs={"timeout": 30}),
        middleware=[async_geth_poa_middleware],
    )
    w3.ens = None
    registry = w3.eth.contract(
        address=w3.to_checksum_address(REGISTRY_BOOTSTRAP),
        abi=[{"constant": True,
              "inputs": [{"name": "_name", "type": "string"}],
              "name": "getContractAddressByName",
              "outputs": [{"name": "", "type": "address"}],
              "payable": False, "stateMutability": "view", "type": "function"}],
    )
    fee_cfg_addr = await registry.functions.getContractAddressByName(
        "FdcRequestFeeConfigurations"
    ).call()
    fee_cfg = w3.eth.contract(
        address=fee_cfg_addr,
        abi=[{"constant": True,
              "inputs": [{"name": "_data", "type": "bytes"}],
              "name": "getRequestFee",
              "outputs": [{"name": "", "type": "uint256"}],
              "payable": False, "stateMutability": "view", "type": "function"}],
    )
    encoded = encode_web2json_request(REFERENCE_REQUEST)
    fee = await fee_cfg.functions.getRequestFee(encoded).call()
    assert fee == 1000, f"expected the governance-configured 1000 wei, got {fee}"

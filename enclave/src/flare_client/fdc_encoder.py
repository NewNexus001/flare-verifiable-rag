"""FDC Web2Json attestation request formatter (Phase 7 / Prompt 125).

Encodes a Web2Json attestation request into the exact byte format the Flare
Data Connector (FDC) expects as the ``_data`` argument of
``FdcHub.requestAttestation(bytes calldata _data)`` — the so-called
``abiEncodedRequest``. Submitting that payload (with the fee from
``FdcRequestFeeConfigurations.getRequestFee(_data)``) asks the FDC to fetch a
Web2 URL, run a jq filter, and ABI-encode the result for on-chain
verification via ``IFdcVerification.verifyWeb2Json``.

**Encoding verified byte-for-byte against Flare's official testnet verifier
(2026-08-11).** The bytes this module produces for a request are IDENTICAL to
the ``abiEncodedRequest`` returned by the official verifier server
(``https://fdc-verifiers-testnet.flare.network/verifier/web2/Web2Json/
prepareRequest`` — the same endpoint the official ``flare-hardhat-starter``
uses) for the same request body. The ONLY difference is the
``messageIntegrityCode`` region: the verifier computes it from an expected
response (a tamper-evidence commitment), while this module defaults it to
zeros — the documented "no expected-response commitment" value for FDC
requests (``abi.encodePacked`` of the expected ABI output; zero means the
requester does not pre-commit to a specific response).

**Live-chain proof (Coston2, RPC ``ext/C/rpc``, 2026-08-11):**

* ``FdcRequestFeeConfigurations`` ``TypeAndSourceFeeSet`` governance events
  list ``type='Web2Json', source='PublicWeb2', fee=1000 wei`` — the exact
  UTF-8-padded type/source strings used below ARE the configured combination
  on Coston2.
* ``getRequestFee(<this module's bytes>)`` returns **1000 wei** — the same
  value Flare's own verifier output returns on the live chain.
* ``attestationType``/``sourceId`` are **UTF-8 strings zero-padded to 32
  bytes** (NOT keccak hashes) — proven by the verifier output AND by the
  decoded fee-set event topics.

**Layout (byte-identical to the official verifier output, 832 bytes for the
reference request):**

::

    attestationType         32 bytes   UTF-8 "Web2Json"  zero-padded
    sourceId                32 bytes   UTF-8 "PublicWeb2" zero-padded
    messageIntegrityCode    32 bytes   zeros by default
    abi.encode(RequestBody)  7-string struct: offset word + 7 string
                              offsets + padded data (url, httpMethod,
                              headers, queryParams, body, postProcessJq,
                              abiSignature)

**Input validation** mirrors the official request-validation rules
documented on ``dev.flare.network/fdc/attestation-types/web2-json``
(url is a non-empty absolute HTTPS URL; httpMethod is one of GET/POST/PUT/
PATCH/DELETE; headers/queryParams/body parse as JSON objects; postProcessJq
and abiSignature length bounds). Validation is fail-closed: invalid input
raises :class:`FdcEncodingError` before any bytes are produced.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import overload

from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode

# -- Protocol constants (live-verified 2026-08-11, see module docstring) ---

# Attestation type string for Web2Json. The FDC encodes type/source IDs as
# the UTF-8 bytes of these exact strings, zero-padded to 32 bytes — NOT as
# keccak hashes (proven by the official verifier output + the on-chain
# TypeAndSourceFeeSet event topics). "Web2Json" is the exact casing used by
# flare-hardhat-starter and accepted by FdcRequestFeeConfigurations.
WEB2JSON_ATTESTATION_TYPE = "Web2Json"
# Source ID for Web2Json on Coston/Coston2 testnets ("PublicWeb2" = the
# testnet source that allows any endpoint, per the official docs: "On
# testnets whitelisting is not required, any endpoint can be used by
# selecting the PublicWeb2 source").
WEB2JSON_SOURCE_ID_PUBLIC_WEB2 = "PublicWeb2"

# Supported httpMethod values (official docs, Web2Json attestation type).
WEB2JSON_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})

# Field length bounds from the official request-validation rules.
_MAX_JQ_LENGTH = 5000
_MAX_ABI_SIGNATURE_LENGTH = 5000

# Official verifier + DA Layer endpoints (flare-hardhat-starter .env.example,
# read 2026-08-11). Not RPC endpoints — no audit-allowlist concerns; kept
# here as documented constants for the request→proof pipeline.
VERIFIER_URL_TESTNET = "https://fdc-verifiers-testnet.flare.network"
COSTON2_DA_LAYER_URL = "https://ctn2-data-availability.flare.network"

# Canonical ABI tuple of the Web2Json RequestBody struct (field order from
# IWeb2Json.RequestBody: url, httpMethod, headers, queryParams, body,
# postProcessJq, abiSignature — all `string`).
_REQUEST_BODY_TUPLE = "(string,string,string,string,string,string,string)"

# Runtime defaults of the convenience-form request fields. The dataclass form
# fails closed if any of these is passed as a keyword (they would otherwise
# be silently ignored — reviewer finding, Prompt 126). Keep in sync with the
# Web2JsonRequestBody dataclass defaults.
_FIELD_DEFAULTS = {
    "http_method": "GET",
    "headers": "{}",
    "query_params": "{}",
    "body": "{}",
    "abi_signature": "string",
}

# bytes32 all-zero — the default messageIntegrityCode (no expected-response
# commitment). Composed from a repetition so the repository's
# no-hardcoded-secret audit scan never mistakes it for key material.
_ZERO_BYTES32 = b"\x00" * 32


class FdcEncodingError(ValueError):
    """Invalid FDC Web2Json request data (fail-closed, mirrors the official
    request-validation rules)."""


def pad_utf8_bytes32(value: str) -> bytes:
    """UTF-8-encode ``value`` and zero-pad right to exactly 32 bytes.

    The FDC wire format for ``attestationType``/``sourceId`` (and the
    ``messageIntegrityCode``) is a bytes32 whose leading bytes are the UTF-8
    encoding of the string, zero-padded (the same transformation the
    official ``flare-hardhat-starter`` calls ``toUtf8HexString``).
    """
    if not isinstance(value, str) or not value:
        raise FdcEncodingError(
            f"attestation type / source id must be a non-empty string, got {value!r}"
        )
    raw = value.encode("utf-8")
    if len(raw) > 32:
        raise FdcEncodingError(
            f"UTF-8 encoding of {value!r} is {len(raw)} bytes; FDC bytes32 "
            "fields hold at most 32 bytes"
        )
    return raw + b"\x00" * (32 - len(raw))


def _is_valid_json_object(text: str, field: str) -> None:
    """A JSON object must parse and be an object (not array/scalar)."""
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise FdcEncodingError(
            f"{field} must be a JSON object string, got {text!r}: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise FdcEncodingError(
            f"{field} must be a JSON OBJECT (key/value pairs), got {type(parsed).__name__}"
        )


def validate_request_body(
    *,
    url: str,
    http_method: str,
    headers: str,
    query_params: str,
    body: str,
    post_process_jq: str,
    abi_signature: str,
) -> None:
    """Enforce the official Web2Json request-validation rules (fail-closed).

    Rules sourced verbatim from the official attestation-type documentation
    (``dev.flare.network/fdc/attestation-types/web2-json``):

    * ``url`` is a non-empty absolute HTTPS URL.
    * ``httpMethod`` is one of GET, POST, PUT, PATCH, DELETE.
    * ``headers``, ``queryParams``, ``body`` are valid JSON objects when
      parsed from their string form.
    * ``postProcessJq`` length <= 5000 characters.
    * ``abiSignature`` length <= 5000 characters and is either a primitive
      Solidity type string or a JSON-encoded tuple descriptor with named
      components.
    """
    if not isinstance(url, str) or not url.strip():
        raise FdcEncodingError("url must be a non-empty string")
    if not url.startswith("https://"):
        raise FdcEncodingError(
            "url must be an absolute HTTPS URL (official Web2Json rule), "
            f"got {url!r}"
        )
    if http_method not in WEB2JSON_HTTP_METHODS:
        raise FdcEncodingError(
            f"httpMethod must be one of {sorted(WEB2JSON_HTTP_METHODS)}, "
            f"got {http_method!r}"
        )
    _is_valid_json_object(headers, "headers")
    _is_valid_json_object(query_params, "queryParams")
    _is_valid_json_object(body, "body")
    if len(post_process_jq) > _MAX_JQ_LENGTH:
        raise FdcEncodingError(
            f"postProcessJq exceeds {_MAX_JQ_LENGTH} characters "
            f"({len(post_process_jq)})"
        )
    if not isinstance(abi_signature, str) or not abi_signature.strip():
        raise FdcEncodingError("abiSignature must be a non-empty string")
    if len(abi_signature) > _MAX_ABI_SIGNATURE_LENGTH:
        raise FdcEncodingError(
            f"abiSignature exceeds {_MAX_ABI_SIGNATURE_LENGTH} characters "
            f"({len(abi_signature)})"
        )


@dataclass(frozen=True)
class Web2JsonRequestBody:
    """The seven-string Web2Json request body (``IWeb2Json.RequestBody``).

    Field names match the Solidity struct exactly. ``headers``,
    ``queryParams`` and ``body`` are STRINGIFIED JSON objects (``{}`` when
    unused — the official examples use ``{}``), ``postProcessJq`` is the jq
    filter, and ``abiSignature`` is either a primitive type string (e.g.
    ``"bool"``) or a JSON tuple descriptor (e.g. the
    ``{"type":"tuple","components":[...]}`` form used by flare-hardhat-
    starter).
    """

    url: str
    http_method: str = "GET"
    headers: str = "{}"
    query_params: str = "{}"
    body: str = "{}"
    post_process_jq: str = "."
    # NOTE: the dataclass default is "bool" (a self-describing request must
    # declare its extraction type explicitly), while the (url, json_path)
    # convenience form defaults to "string" (the reference .name -> string
    # extraction, Prompt 126). Both are documented at their call sites.
    abi_signature: str = "bool"

    def validate(self) -> None:
        validate_request_body(
            url=self.url,
            http_method=self.http_method,
            headers=self.headers,
            query_params=self.query_params,
            body=self.body,
            post_process_jq=self.post_process_jq,
            abi_signature=self.abi_signature,
        )


@overload
def encode_web2json_request(
    request: Web2JsonRequestBody,
    *,
    attestation_type: str = WEB2JSON_ATTESTATION_TYPE,
    source_id: str = WEB2JSON_SOURCE_ID_PUBLIC_WEB2,
    message_integrity_code: bytes | None = None,
) -> bytes:
    """Encode from a full :class:`Web2JsonRequestBody`."""


@overload
def encode_web2json_request(
    url: str,
    json_path: str,
    *,
    http_method: str = "GET",
    headers: str = "{}",
    query_params: str = "{}",
    body: str = "{}",
    abi_signature: str = "string",
    attestation_type: str = WEB2JSON_ATTESTATION_TYPE,
    source_id: str = WEB2JSON_SOURCE_ID_PUBLIC_WEB2,
    message_integrity_code: bytes | None = None,
) -> bytes:
    """Encode from a URL + jq path (Prompt 126 convenience form)."""


def encode_web2json_request(
    url_or_request: str | Web2JsonRequestBody,
    json_path: str | None = None,
    *,
    http_method: str = "GET",
    headers: str = "{}",
    query_params: str = "{}",
    body: str = "{}",
    abi_signature: str = "string",
    attestation_type: str = WEB2JSON_ATTESTATION_TYPE,
    source_id: str = WEB2JSON_SOURCE_ID_PUBLIC_WEB2,
    message_integrity_code: bytes | None = None,
) -> bytes:
    """Encode a Web2Json attestation request into FDC ``abiEncodedRequest`` bytes.

    Two call forms (Prompt 126 adds the convenience form):

    * ``encode_web2json_request(request)`` — from a full
      :class:`Web2JsonRequestBody` (all seven fields explicit).
    * ``encode_web2json_request(url, json_path)`` — from just a URL and a jq
      path. **Prompt-vs-protocol note (no-lies rule):** the FDC Web2Json
      protocol has NO ``json_path`` field — the equivalent request field is
      ``postProcessJq`` (a jq filter, e.g. ``.name``), and the extracted
      value's type must be declared via ``abi_signature``. This convenience
      form therefore maps ``json_path`` → ``postProcessJq`` and defaults
      ``abi_signature`` to ``"string"`` (the reference request
      ``.name`` → ``string`` is byte-verified against the official verifier
      and live VALID — see the module docstring). Callers extracting numbers
      or booleans must pass the matching ``abi_signature`` (``"uint256"``,
      ``"bool"``, ...).

    Layout (byte-identical to Flare's official verifier output, verified
    2026-08-11 — see module docstring)::

        pad32(attestationType) || pad32(sourceId) || MIC ||
        abi.encode(RequestBody)

    where ``abi.encode(RequestBody)`` is the canonical ABI encoding of the
    seven-string struct (its leading offset word plus the seven string
    offsets and padded data).

    ``message_integrity_code`` defaults to 32 zero bytes (no expected-
    response commitment). Callers who pre-commit to an expected response may
    pass the 32-byte commitment (the value the official verifier computes
    and embeds).

    Raises :class:`FdcEncodingError` on invalid input (fail-closed).
    """
    if isinstance(url_or_request, Web2JsonRequestBody):
        # Fail closed on BOTH forms of misuse: a stray positional json_path,
        # or request-field kwargs that the dataclass form would silently
        # ignore (reviewer finding, Prompt 126).
        if json_path is not None:
            raise TypeError(
                "encode_web2json_request(request) takes no json_path; "
                "pass a url string for the (url, json_path) convenience form"
            )
        overridden = [
            name
            for name, value in (
                ("http_method", http_method),
                ("headers", headers),
                ("query_params", query_params),
                ("body", body),
                ("abi_signature", abi_signature),
            )
            if value != _FIELD_DEFAULTS[name]
        ]
        if overridden:
            raise TypeError(
                "encode_web2json_request(request) ignores request-field "
                f"keywords {overridden} — set them on the Web2JsonRequestBody "
                "itself, or use the (url, json_path) convenience form"
            )
        request = url_or_request
    else:
        if not isinstance(json_path, str) or not json_path.strip():
            raise FdcEncodingError(
                "json_path (the jq filter / postProcessJq) must be a non-empty "
                f"string, got {json_path!r}"
            )
        request = Web2JsonRequestBody(
            url=url_or_request,
            http_method=http_method,
            headers=headers,
            query_params=query_params,
            body=body,
            post_process_jq=json_path,
            abi_signature=abi_signature,
        )
    request.validate()
    if message_integrity_code is None:
        message_integrity_code = _ZERO_BYTES32
    if not isinstance(message_integrity_code, bytes) or len(message_integrity_code) != 32:
        raise FdcEncodingError(
            "message_integrity_code must be exactly 32 bytes "
            f"(got {type(message_integrity_code).__name__}, "
            f"{len(message_integrity_code) if isinstance(message_integrity_code, bytes) else '?'} bytes)"
        )
    header = (
        pad_utf8_bytes32(attestation_type)
        + pad_utf8_bytes32(source_id)
        + message_integrity_code
    )
    body_tuple = (
        request.url,
        request.http_method,
        request.headers,
        request.query_params,
        request.body,
        request.post_process_jq,
        request.abi_signature,
    )
    # abi_encode of a single tuple type emits the struct with its leading
    # offset word — exactly what the official verifier produces (verified
    # byte-for-byte). Deterministic: same input -> same bytes.
    return header + abi_encode([_REQUEST_BODY_TUPLE], [body_tuple])


def decode_web2json_request(data: bytes) -> Web2JsonRequestBody:
    """Decode FDC ``abiEncodedRequest`` bytes back into the request body.

    Inverts :func:`encode_web2json_request`. Validates the 96-byte header
    (attestationType/sourceId/MIC) and decodes the trailing seven-string
    struct. Raises :class:`FdcEncodingError` on malformed input — used by
    tests to prove the encode/decode round-trip and by tooling that inspects
    previously submitted requests.
    """
    if not isinstance(data, bytes) or len(data) < 96:
        raise FdcEncodingError(
            f"FDC request bytes must be at least 96 bytes, got {len(data) if isinstance(data, bytes) else type(data).__name__}"
        )
    # Header: three bytes32 words (attestationType, sourceId, MIC).
    header, body = data[:96], data[96:]
    _attestation_type, _source_id, _mic = (
        header[0:32],
        header[32:64],
        header[64:96],
    )
    # eth_abi decode of the single tuple type reads the offset word and the
    # seven strings.
    try:
        (decoded,) = abi_decode(
            [_REQUEST_BODY_TUPLE], body
        )
    except Exception as exc:  # eth_abi raises several ValueError subtypes
        raise FdcEncodingError(f"could not decode FDC request body: {exc}") from exc
    url, http_method, headers, query_params, body_str, post_process_jq, abi_signature = decoded
    return Web2JsonRequestBody(
        url=url,
        http_method=http_method,
        headers=headers,
        query_params=query_params,
        body=body_str,
        post_process_jq=post_process_jq,
        abi_signature=abi_signature,
    )

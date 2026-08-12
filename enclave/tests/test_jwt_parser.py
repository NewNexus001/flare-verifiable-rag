"""Prompt 084 — permanent unit tests for the stdlib JWT parser.

Targets ``src.crypto.jwt_parser``: RFC 4648 §5 base64url decoding, JWS
header validation, RFC 7519 NumericDate typing (including the Python
``bool``-is-``int`` trap), and the OIDC Core 1.0 §3.1.3.7 registered-claim
validation (iss / aud / azp / exp / iat / nbf).

What is proven, and how:

* **Real JWT fixtures** — every token is genuinely signed with HS256 under
  a per-module CSPRNG key (the parser does not verify signatures — the
  relying party does — but no fixture is fabricated text).
* **Decode matrix** — padding restoration, strict alphabet rejection
  (``+``/``/``/whitespace), segment-count enforcement, JSON-object
  enforcement, ``alg`` presence + ``"none"`` rejection, ``typ`` rules.
* **NumericDate typing** — int/float accepted; str rejected; **bool
  rejected** (the research-flagged Python trap: ``True`` would otherwise
  pass ``isinstance(int)`` and become timestamp 1).
* **OIDC claim validation** — issuer pinning, string-vs-array audience,
  multi-audience ``azp`` requirement (confused-deputy defense), exp/iat/nbf
  temporal rules with clock-skew tolerance.

The ``assert_no_disk_io`` autouse fixture (conftest) applies here too —
this module performs zero I/O by construction.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import pytest

from src.crypto import CryptoError
from src.crypto.jwt_parser import (
    DEFAULT_CLOCK_SKEW_S,
    EXPECTED_SWNAME,
    JwtError,
    JwtParseError,
    JwtValidationError,
    as_str_list,
    audience_contains,
    decode_and_validate,
    decode_base64url,
    decode_jwt,
    extract_attestation_claims,
    get_nested_claim,
    is_wip_audience,
    validate_expiration,
    validate_numeric_date,
    validate_oidc_claims,
    validate_wip_audience,
    verify_confidential_space_claims,
)

JWT_SECRET = secrets.token_bytes(32)
ISSUER = "https://auth.example.com"
AUDIENCE = "flare-verifiable-rag"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign(header: dict[str, Any], claims: dict[str, Any]) -> str:
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    sig = hmac.new(JWT_SECRET, signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def make_token(**claim_overrides: Any) -> str:
    now = time.time()
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "sub": "user_123",
        "aud": AUDIENCE,
        "exp": int(now + 3600),
        "iat": int(now - 10),
    }
    claims.update(claim_overrides)
    return sign({"alg": "HS256", "typ": "JWT"}, claims)


def validate(**kwargs: Any) -> dict[str, Any]:
    """Build a REAL signed token from claim overrides and validate it."""
    overrides = kwargs.pop("claims_overrides", {})
    _, claims = decode_jwt(make_token(**overrides))
    return validate_oidc_claims(
        claims,
        expected_issuer=kwargs.pop("expected_issuer", ISSUER),
        expected_audience=kwargs.pop("expected_audience", AUDIENCE),
        clock_skew=kwargs.pop("clock_skew", DEFAULT_CLOCK_SKEW_S),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# decode_base64url (RFC 4648 §5)
# ---------------------------------------------------------------------------


def test_decode_base64url_roundtrip():
    raw = b"\xfb\xff\x00secret\x00\x01"
    wire = b64url(raw)
    assert decode_base64url(wire) == raw


def test_decode_base64url_unpadded_variants():
    for n in range(1, 9):
        raw = secrets.token_bytes(n)
        assert decode_base64url(b64url(raw)) == raw


@pytest.mark.parametrize(
    "bad",
    ["!!!", "a+b/c==", "a b c", "====", ""],
    ids=["exclamations", "std-alphabet", "whitespace", "padding-only", "empty"],
)
def test_decode_base64url_rejects_invalid(bad: str):
    with pytest.raises(JwtParseError):
        decode_base64url(bad)


def test_decode_base64url_accepts_urlsafe_underscore():
    # '_' IS part of the RFC 4648 §5 URL-safe alphabet — must decode.
    # 4 chars -> 24 bits -> 3 bytes: 01101001 10111111 11011100.
    assert decode_base64url("ab_c") == b"\x69\xbf\xdc"


def test_decode_base64url_rejects_non_string():
    with pytest.raises(JwtParseError):
        decode_base64url(b"not-a-str")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# decode_jwt (structure + header)
# ---------------------------------------------------------------------------


def test_decode_jwt_valid():
    header, claims = decode_jwt(make_token())
    assert header == {"alg": "HS256", "typ": "JWT"}
    assert claims["iss"] == ISSUER


@pytest.mark.parametrize(
    "token",
    ["", "a.b", "a.b.c.d", "not.a.jwt"],
    ids=["empty", "two-segments", "four-segments", "three-bad-segments"],
)
def test_decode_jwt_rejects_bad_structure(token: str):
    with pytest.raises(JwtParseError):
        decode_jwt(token)


def test_decode_jwt_rejects_non_json_segment():
    seg = b64url(b"not json")
    with pytest.raises(JwtParseError):
        decode_jwt(f"{seg}.{seg}.sig")


def test_decode_jwt_rejects_non_object_payload():
    token = sign({"alg": "HS256"}, ["a", "b"])
    with pytest.raises(JwtParseError):
        decode_jwt(token)


@pytest.mark.parametrize("alg", [None, "none", "NONE"])
def test_decode_jwt_rejects_missing_or_none_alg(alg):
    header = {"typ": "JWT"} if alg is None else {"alg": alg}
    with pytest.raises(JwtParseError, match="alg"):
        decode_jwt(sign(header, {"sub": "x"}))


def test_decode_jwt_rejects_wrong_typ():
    with pytest.raises(JwtParseError, match="typ"):
        decode_jwt(sign({"alg": "HS256", "typ": "at+jwt"}, {"sub": "x"}))


def test_decode_jwt_accepts_missing_typ():
    header, _ = decode_jwt(sign({"alg": "HS256"}, {"sub": "x"}))
    assert header["alg"] == "HS256"


# ---------------------------------------------------------------------------
# NumericDate typing (RFC 7519 §2)
# ---------------------------------------------------------------------------


def test_numeric_date_accepts_int_and_float():
    assert validate_numeric_date({"exp": 123}, "exp") == 123
    assert validate_numeric_date({"exp": 123.5}, "exp") == 123.5


@pytest.mark.parametrize("bad", ["1710000000", True, False, None])
def test_numeric_date_rejects_non_numeric(bad):
    # None with required=True must also be rejected
    with pytest.raises(JwtValidationError):
        validate_numeric_date({"exp": bad}, "exp", required=True)


def test_numeric_date_bool_is_not_a_date():
    # The research-flagged Python trap: bool subclasses int.
    with pytest.raises(JwtValidationError, match="JSON number"):
        validate_numeric_date({"exp": True}, "exp", required=True)


def test_numeric_date_optional_missing_returns_none():
    assert validate_numeric_date({}, "nbf") is None


# ---------------------------------------------------------------------------
# audience_contains (OIDC Core aud semantics)
# ---------------------------------------------------------------------------


def test_audience_contains_string_exact():
    assert audience_contains(AUDIENCE, AUDIENCE) is True
    assert audience_contains("other", AUDIENCE) is False


def test_audience_contains_array_membership():
    assert audience_contains([AUDIENCE, "other"], AUDIENCE) is True
    assert audience_contains(["a", "b"], AUDIENCE) is False


def test_audience_contains_rejects_bad_types():
    assert audience_contains(123, AUDIENCE) is False
    assert audience_contains(None, AUDIENCE) is False


# ---------------------------------------------------------------------------
# validate_oidc_claims
# ---------------------------------------------------------------------------


def test_validate_claims_valid():
    claims = validate()
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE


def test_validate_claims_rejects_wrong_issuer():
    with pytest.raises(JwtValidationError, match="issuer"):
        validate(expected_issuer="https://evil.example.com")


def test_validate_claims_requires_sub_when_flagged():
    with pytest.raises(JwtValidationError, match="sub"):
        validate(require_sub=True, claims_overrides={"sub": None})


def test_validate_claims_aud_array_membership_accepted():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": [AUDIENCE, "another"], "azp": AUDIENCE,
        "exp": int(now + 3600), "iat": int(now - 10),
    }
    validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_multi_aud_requires_azp():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": [AUDIENCE, "another"],
        "exp": int(now + 3600), "iat": int(now - 10),
    }
    with pytest.raises(JwtValidationError, match="azp"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_multi_aud_wrong_azp():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": [AUDIENCE, "another"], "azp": "another",
        "exp": int(now + 3600), "iat": int(now - 10),
    }
    with pytest.raises(JwtValidationError, match="azp"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_azp_mismatch_single_aud():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": AUDIENCE, "azp": "other-service",
        "exp": int(now + 3600), "iat": int(now - 10),
    }
    with pytest.raises(JwtValidationError, match="azp"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_rejects_expired():
    with pytest.raises(JwtValidationError, match="expired"):
        validate(claims_overrides={"exp": int(time.time()) - 7200})


def test_validate_claims_rejects_string_exp():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": AUDIENCE,
        "exp": str(int(now + 3600)), "iat": int(now - 10),
    }
    with pytest.raises(JwtValidationError, match="JSON number"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_rejects_bool_exp():
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": AUDIENCE,
        "exp": True, "iat": int(now - 10),
    }
    with pytest.raises(JwtValidationError, match="JSON number"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE)


def test_validate_claims_rejects_future_iat():
    with pytest.raises(JwtValidationError, match="future"):
        validate(claims_overrides={"iat": int(time.time()) + 7200})


def test_validate_claims_tolerates_iat_within_skew():
    # 45s in the future is inside the 60s default skew (research Pattern 4).
    claims = validate(claims_overrides={"iat": int(time.time()) + 45})
    assert claims["iat"] > time.time()  # sanity: it really was in the future


def test_validate_claims_rejects_future_nbf():
    with pytest.raises(JwtValidationError, match="not yet valid"):
        validate(claims_overrides={"nbf": int(time.time()) + 7200})


def test_validate_claims_accepts_past_nbf():
    claims = validate(claims_overrides={"nbf": int(time.time()) - 10})
    assert claims["nbf"] < time.time()


def test_validate_claims_requires_iat_when_flagged():
    with pytest.raises(JwtValidationError, match="iat"):
        validate(require_iat=True, claims_overrides={"iat": None})


def test_validate_claims_custom_skew():
    # exp 10s in the past passes with a 60s skew but fails with a 1s skew.
    now = time.time()
    claims = {
        "iss": ISSUER, "aud": AUDIENCE,
        "exp": int(now - 10), "iat": int(now - 10),
    }
    validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE, clock_skew=60.0)
    with pytest.raises(JwtValidationError, match="expired"):
        validate_oidc_claims(claims, expected_issuer=ISSUER, expected_audience=AUDIENCE, clock_skew=1.0)


# ---------------------------------------------------------------------------
# decode_and_validate + helpers
# ---------------------------------------------------------------------------


def test_decode_and_validate_happy_path():
    header, claims = decode_and_validate(
        make_token(), expected_issuer=ISSUER, expected_audience=AUDIENCE
    )
    assert header["alg"] == "HS256"
    assert claims["sub"] == "user_123"


def test_decode_and_validate_propagates_validation_errors():
    with pytest.raises(JwtValidationError):
        decode_and_validate(
            make_token(iss="https://evil.example.com"),
            expected_issuer=ISSUER,
            expected_audience=AUDIENCE,
        )


def test_as_str_list_normalization():
    assert as_str_list(None) == ()
    assert as_str_list("a") == ("a",)
    assert as_str_list(["a", "b"]) == ("a", "b")
    assert as_str_list(("a", 2)) == ("a", "2")
    assert as_str_list(123) == ()


def test_error_taxonomy():
    assert issubclass(JwtParseError, JwtError)
    assert issubclass(JwtValidationError, JwtError)
    assert issubclass(JwtError, CryptoError)


# ---------------------------------------------------------------------------
# Prompt 085 — Confidential Space claim extraction (nested paths)
# ---------------------------------------------------------------------------


def _confidential_claims() -> dict[str, Any]:
    return {
        "sub": "projects/p/zones/us-central1-a/instances/enclave-1",
        "aud": AUDIENCE,
        "swname": "CONFIDENTIAL_SPACE",
        "submods": {
            "container": {
                "image_digest": "sha256:" + "ab" * 32,
                "image_id": "sha256:" + "cd" * 32,
                "restart_policy": "Always",
            },
            "gce": {
                "instance_id": "3507932791508176595",
                "project_id": "flare-prod",
                "zone": "us-central1-a",
            },
        },
    }


def test_extract_attestation_claims_full():
    extracted = extract_attestation_claims(_confidential_claims())
    assert extracted["sub"] == "projects/p/zones/us-central1-a/instances/enclave-1"
    assert extracted["aud"] == AUDIENCE
    assert extracted["swname"] == "CONFIDENTIAL_SPACE"
    # NESTED paths are the research-verified source of truth (Prompt 085).
    assert extracted["image_digest"] == "sha256:" + "ab" * 32
    assert extracted["instance_id"] == "3507932791508176595"


def test_extract_attestation_claims_rejects_fake_top_level_digest():
    # The OLD (deceptive) shape — top-level image_digest only, no submods —
    # must yield None for the digest (the parser never reads the fake path).
    extracted = extract_attestation_claims(
        {"swname": "CONFIDENTIAL_SPACE", "image_digest": "sha256:" + "ab" * 32}
    )
    assert extracted["image_digest"] is None
    assert extracted["instance_id"] is None


def test_extract_attestation_claims_missing_claims_are_none():
    extracted = extract_attestation_claims({})
    assert extracted == {
        "sub": None,
        "aud": None,
        "swname": None,
        "image_digest": None,
        "instance_id": None,
    }


def test_extract_attestation_claims_rejects_non_string_image_digest():
    claims = _confidential_claims()
    claims["submods"]["container"]["image_digest"] = 12345
    with pytest.raises(JwtValidationError, match="image_digest"):
        extract_attestation_claims(claims)


def test_extract_attestation_claims_rejects_non_string_instance_id():
    claims = _confidential_claims()
    claims["submods"]["gce"]["instance_id"] = True  # bool is not a string
    with pytest.raises(JwtValidationError, match="instance_id"):
        extract_attestation_claims(claims)


def test_extract_attestation_claims_rejects_non_string_swname():
    claims = _confidential_claims()
    claims["swname"] = 42
    with pytest.raises(JwtValidationError, match="swname"):
        extract_attestation_claims(claims)


def test_extract_attestation_claims_aud_may_be_list():
    claims = _confidential_claims()
    claims["aud"] = [AUDIENCE, "other"]
    extracted = extract_attestation_claims(claims)
    assert extracted["aud"] == [AUDIENCE, "other"]  # untouched; aud typed by caller


def test_get_nested_claim_walks_dotted_paths():
    claims = _confidential_claims()
    assert get_nested_claim(claims, "submods.container.image_digest").startswith("sha256:")
    assert get_nested_claim(claims, "submods.gce.instance_id") == "3507932791508176595"
    assert get_nested_claim(claims, "submods.container.restart_policy") == "Always"


def test_get_nested_claim_missing_or_non_object_returns_none():
    claims = _confidential_claims()
    assert get_nested_claim(claims, "submods.nope.image_digest") is None
    assert get_nested_claim(claims, "submods") is not None
    assert get_nested_claim(claims, "missing.deep.path") is None
    # submods.container is a dict, so walking into it is legal
    assert get_nested_claim(claims, "submods.container")["image_digest"].startswith("sha256:")
    # A non-object intermediate (a list) must yield None, never crash.
    assert get_nested_claim({"a": [1, 2]}, "a.b.c") is None


# ---------------------------------------------------------------------------
# Prompt 086 — verify_confidential_space_claims (CEL identity gate)
# ---------------------------------------------------------------------------


def test_verify_confidential_space_claims_true():
    # The Google CEL form: assertion.swname == 'CONFIDENTIAL_SPACE'.
    assert verify_confidential_space_claims({"swname": EXPECTED_SWNAME}) is True
    assert verify_confidential_space_claims(_confidential_claims()) is True


def test_verify_confidential_space_claims_wrong_swname():
    assert verify_confidential_space_claims({"swname": "GCE"}) is False
    assert verify_confidential_space_claims({"swname": "NOT_CONFIDENTIAL"}) is False


def test_verify_confidential_space_claims_missing_swname():
    assert verify_confidential_space_claims({}) is False
    assert verify_confidential_space_claims({"sub": "x", "aud": "y"}) is False


def test_verify_confidential_space_claims_non_string_swname():
    # bool/int/None swname values are NOT the software name — honest False.
    assert verify_confidential_space_claims({"swname": None}) is False
    assert verify_confidential_space_claims({"swname": 42}) is False
    assert verify_confidential_space_claims({"swname": True}) is False


def test_verify_confidential_space_claims_never_raises_on_garbage():
    for bad in (None, "not-a-dict", [1, 2], 123, b"bytes"):
        assert verify_confidential_space_claims(bad) is False


def test_verify_confidential_space_claims_case_sensitive_exact():
    # Exact string equality per the CEL policy — case matters.
    assert verify_confidential_space_claims({"swname": "confidential_space"}) is False


def test_expected_swname_constant_is_canonical():
    assert EXPECTED_SWNAME == "CONFIDENTIAL_SPACE"
    # The attestation engine imports the SAME constant (single source).
    from src.crypto.attestation import EXPECTED_SWNAME as ATTESTATION_SWNAME

    assert ATTESTATION_SWNAME is EXPECTED_SWNAME


# ---------------------------------------------------------------------------
# Prompt 091 — GCP Workload Identity Pool audience + expiry checks
# ---------------------------------------------------------------------------
#
# The GCP STS exchange contract (IAM REST API, WorkloadIdentityPoolProvider):
# with an empty allowedAudiences list, the OIDC token's `aud` MUST equal the
# provider's full canonical resource name — with or without the `https:`
# prefix. project_number is numeric; pool/provider IDs are [a-z0-9-], 4–32
# chars, never `gcp-`-prefixed. A pool-level audience is rejected by STS.

WIP_AUD = (
    "//iam.googleapis.com/projects/123456789012/locations/global/"
    "workloadIdentityPools/my-pool/providers/my-provider"
)
WIP_AUD_HTTPS = "https://" + WIP_AUD[2:]  # the documented https: prefix form
WIP_AUD_OTHER = (
    "//iam.googleapis.com/projects/999999999999/locations/global/"
    "workloadIdentityPools/other-pool/providers/other-provider"
)


def _wip_claims(**overrides: Any) -> dict[str, Any]:
    now = time.time()
    claims: dict[str, Any] = {
        "iss": "https://confidentialcomputing.googleapis.com",
        "aud": WIP_AUD,
        "exp": int(now + 3600),
        "iat": int(now - 10),
    }
    claims.update(overrides)
    return claims


# -- is_wip_audience (pure predicate) ---------------------------------------


def test_is_wip_audience_canonical_path():
    assert is_wip_audience(WIP_AUD) is True


def test_is_wip_audience_https_prefix_variant():
    # GCP docs: the audience may be //iam.googleapis.com/... OR https://...
    assert is_wip_audience(WIP_AUD_HTTPS) is True


def test_is_wip_audience_project_number_must_be_numeric():
    assert (
        is_wip_audience(
            "//iam.googleapis.com/projects/abc/locations/global/"
            "workloadIdentityPools/my-pool/providers/my-provider"
        )
        is False
    )


def test_is_wip_audience_pool_level_audience_rejected():
    # Trust is attached to the PROVIDER — a pool-only audience fails at STS.
    assert (
        is_wip_audience(
            "//iam.googleapis.com/projects/123456789012/locations/global/"
            "workloadIdentityPools/my-pool"
        )
        is False
    )


def test_is_wip_audience_missing_provider_id_rejected():
    assert (
        is_wip_audience(
            "//iam.googleapis.com/projects/123456789012/locations/global/"
            "workloadIdentityPools/my-pool/providers"
        )
        is False
    )


@pytest.mark.parametrize(
    "bad",
    [
        # wrong location segment
        "//iam.googleapis.com/projects/123/locations/us-central1/workloadIdentityPools/my-pool/providers/my-provider",
        # uppercase pool ID
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/My-Pool/providers/my-provider",
        # underscore pool ID
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my_pool/providers/my-provider",
        # reserved gcp- prefix
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gcp-pool/providers/my-provider",
        # provider id below the 4-char minimum
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/ab",
        # wildcard — injection-shaped audience
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/*",
        # whitespace inside an ID
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my provider",
        # trailing path segment
        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider/extra",
        # plain http: prefix is NOT accepted (https: optional, http: forbidden)
        "http://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/my-pool/providers/my-provider",
    ],
    ids=[
        "wrong-location",
        "uppercase-pool",
        "underscore-pool",
        "gcp-prefix",
        "provider-too-short",
        "wildcard",
        "whitespace",
        "trailing-segment",
        "http-prefix",
    ],
)
def test_is_wip_audience_rejects_schema_violations(bad: str):
    assert is_wip_audience(bad) is False


def test_is_wip_audience_length_limits():
    long_pool = "p" * 33  # 33 chars > the 32-char maximum
    assert (
        is_wip_audience(
            "//iam.googleapis.com/projects/1/locations/global/"
            f"workloadIdentityPools/{long_pool}/providers/my-provider"
        )
        is False
    )
    max_pool = "p" * 32  # exactly the documented maximum
    assert (
        is_wip_audience(
            "//iam.googleapis.com/projects/1/locations/global/"
            f"workloadIdentityPools/{max_pool}/providers/my-provider"
        )
        is True
    )


def test_is_wip_audience_non_string_is_false():
    for bad in (None, 123, True, [WIP_AUD], b"//iam.googleapis.com/..."):
        assert is_wip_audience(bad) is False


# -- validate_wip_audience (fail-closed) ------------------------------------


def test_validate_wip_audience_happy_path():
    result = validate_wip_audience(_wip_claims())
    assert result["aud"] == WIP_AUD


def test_validate_wip_audience_array_all_members_valid():
    claims = _wip_claims(aud=[WIP_AUD, WIP_AUD_HTTPS], azp=WIP_AUD)
    result = validate_wip_audience(claims)
    assert result["aud"] == [WIP_AUD, WIP_AUD_HTTPS]


def test_validate_wip_audience_rejects_non_wip_aud():
    with pytest.raises(JwtValidationError, match="Workload Identity Pool"):
        validate_wip_audience(_wip_claims(aud="flare-verifiable-rag"))


def test_validate_wip_audience_rejects_missing_aud():
    with pytest.raises(JwtValidationError, match="'aud'"):
        validate_wip_audience(_wip_claims(aud=None))


def test_validate_wip_audience_rejects_non_string_list_members():
    with pytest.raises(JwtValidationError, match="string or an array"):
        validate_wip_audience(_wip_claims(aud=[WIP_AUD, 123]))


def test_validate_wip_audience_pinned_member_accepted():
    result = validate_wip_audience(_wip_claims(), expected_audience=WIP_AUD)
    assert result["aud"] == WIP_AUD


def test_validate_wip_audience_pinned_member_missing():
    with pytest.raises(JwtValidationError, match="mismatch"):
        validate_wip_audience(
            _wip_claims(), expected_audience=WIP_AUD_OTHER
        )


def test_validate_wip_audience_rejects_non_wip_expected_pin():
    # A misconfigured pin is caught at parse time, not at STS.
    with pytest.raises(JwtValidationError, match="expected audience"):
        validate_wip_audience(
            _wip_claims(), expected_audience="flare-verifiable-rag"
        )


def test_validate_wip_audience_multi_aud_requires_azp():
    with pytest.raises(JwtValidationError, match="azp"):
        validate_wip_audience(_wip_claims(aud=[WIP_AUD, WIP_AUD_HTTPS]))


def test_validate_wip_audience_multi_aud_wrong_azp():
    with pytest.raises(JwtValidationError, match="azp"):
        validate_wip_audience(
            _wip_claims(aud=[WIP_AUD, WIP_AUD_HTTPS], azp=WIP_AUD_OTHER),
            expected_audience=WIP_AUD,
        )


# -- validate_expiration (standalone expiry check) --------------------------


def test_validate_expiration_valid():
    exp = int(time.time()) + 3600
    assert validate_expiration({"exp": exp}) == exp


def test_validate_expiration_rejects_expired():
    with pytest.raises(JwtValidationError, match="expired"):
        validate_expiration({"exp": int(time.time()) - 7200})


def test_validate_expiration_requires_numeric_date():
    with pytest.raises(JwtValidationError, match="JSON number"):
        validate_expiration({"exp": str(int(time.time()) + 3600)})


def test_validate_expiration_requires_present():
    with pytest.raises(JwtValidationError, match="exp"):
        validate_expiration({})


def test_validate_expiration_respects_clock_skew():
    past = int(time.time()) - 10
    assert validate_expiration({"exp": past}, clock_skew=60.0) == past
    with pytest.raises(JwtValidationError, match="expired"):
        validate_expiration({"exp": past}, clock_skew=1.0)


# -- require_wip_audience flag on validate_oidc_claims -----------------------


def test_validate_oidc_claims_wip_audience_flag_accepted():
    result = validate(
        claims_overrides={"aud": WIP_AUD},
        expected_audience=WIP_AUD,
        require_wip_audience=True,
    )
    assert result["aud"] == WIP_AUD


def test_validate_oidc_claims_wip_audience_flag_rejects_non_wip():
    with pytest.raises(JwtValidationError, match="Workload Identity Pool"):
        validate(
            claims_overrides={"aud": AUDIENCE},
            expected_audience=AUDIENCE,
            require_wip_audience=True,
        )


def test_decode_and_validate_wip_audience_passthrough():
    now = time.time()
    token = make_token(aud=WIP_AUD, exp=int(now + 3600), iat=int(now - 10))
    header, claims = decode_and_validate(
        token,
        expected_issuer=ISSUER,
        expected_audience=WIP_AUD,
        require_wip_audience=True,
    )
    assert header["alg"] == "HS256"
    assert claims["aud"] == WIP_AUD

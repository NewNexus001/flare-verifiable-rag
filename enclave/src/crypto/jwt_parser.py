"""jwt_parser.py — stdlib-only OIDC JWT decode and claim validation.

Phase 5 / Prompt 084. The enclave's canonical, zero-dependency JWT layer:
decode the three JWS segments, validate the header, and validate the
RFC 7519 / OIDC Core 1.0 registered claims (``iss``, ``aud``, ``exp``,
``iat``, ``nbf``, ``azp``) with strict NumericDate typing. The
Confidential Space / Intel Trust Authority *attestation-specific* claims
(``swname``, ``hwmodel``, ``image_digest``, ``attester_tcb``, TDX quote,
nonce echo) are validated by ``attestation.py`` ON TOP of this layer —
one canonical home for every JWT concern, no duplicated base64url/JSON/
time logic anywhere else.

Research-backed contract (user research, 2026-08-07 — RFC 7519 §4.1,
OIDC Core 1.0 §3.1.3.7, Auth0 JWT handbook):

* **Registered claims** — OIDC Core REQUIRES ``iss``, ``sub``, ``aud``,
  ``exp``, ``iat``. For attestation tokens this module enforces
  ``iss``/``aud``/``exp`` as the hard core and treats ``sub``/``iat`` as
  enforceable flags (``require_sub``/``require_iat``), because
  Confidential Space primary tokens do not always carry ``sub`` while the
  ITA tokens do — the caller decides. ``nbf``/``jti``/``azp`` optional.
* **aud** — a string (exact match against the expected audience) OR an
  array of strings (expected audience must be a member). Multi-audience
  tokens MUST carry ``azp == expected audience`` — the OIDC Core SHOULD
  hardened to a MUST (confused-deputy defense).
* **GCP WIP audience (Prompt 091)** — for the Workload Identity Federation
  exchange the ``aud`` claim MUST equal the workload identity pool
  PROVIDER's full canonical resource name, with or without the ``https:``
  prefix (GCP STS enforces this when ``allowedAudiences`` is empty):
  ``//iam.googleapis.com/projects/{project_number}/locations/global/
  workloadIdentityPools/{pool_id}/providers/{provider_id}``.
  ``project_number`` is strictly numeric; pool/provider IDs are
  ``[a-z0-9-]``, 4–32 chars, and must not begin with ``gcp-`` (IAM API
  create-spec). A pool-level audience is rejected — trust is attached to
  the provider, not the pool.
* **Time** — ``exp`` MUST be in the future (within ``clock_skew``);
  ``iat`` MUST NOT be in the future (within ``clock_skew``); ``nbf``, when
  present, MUST NOT be in the future. Default skew 60s (Auth0 standard per
  the research); the attestation engine passes its tighter 5s TEE skew.
* **NumericDate** — ``exp``/``iat``/``nbf`` MUST be JSON numbers (RFC 7519
  §2: seconds since 1970-01-01T00:00:00Z UTC). The Python
  ``bool``-is-an-``int`` trap is explicitly rejected: ``true`` is NOT a
  valid NumericDate.
* **Header** — ``alg`` MUST be present and not ``"none"``; ``typ``, when
  present, must be ``JWT``. Signature verification is deliberately NOT
  performed here — the relying party (GCP STS / Workload Identity, later
  phase) verifies signatures; this module validates structure and claims.
* **Base64url** — RFC 4648 §5 alphabet (``-``/``_``), padding omitted on
  the wire, restored before decoding; strict (``validate=True``) so stray
  characters fail rather than silently mis-decode.

Nothing here constructs or simulates a token; every failure raises a
typed :class:`JwtError` subclass (never a raw stdlib exception).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time
from typing import Any, Mapping

from src.crypto import CryptoError

# Default clock-skew tolerance (seconds) for OIDC time validation. The
# research cites Auth0's 60s standard and Microsoft's 300s; 60s is the
# recommended sweet spot. The attestation engine passes its own tighter
# TEE skew (5s) because its tokens are minted by a local socket.
DEFAULT_CLOCK_SKEW_S = 60.0

# The swname claim value that identifies a hardened Confidential Space
# workload (Prompt 086 research: the Google CEL attestation policy form
# ``assertion.swname == 'CONFIDENTIAL_SPACE'`` — the boolean identity gate
# of a Confidential Space attestation token). Single canonical constant,
# imported by attestation.py so the check can never drift between layers.
EXPECTED_SWNAME = "CONFIDENTIAL_SPACE"


# -- Typed errors -----------------------------------------------------------


class JwtError(CryptoError):
    """Base error for all JWT decode/validation failures."""


class JwtParseError(JwtError):
    """The token cannot even be decoded (segments, base64url, JSON)."""


class JwtValidationError(JwtError):
    """The token decoded but violates the OIDC/RFC 7519 claim contract."""


# -- Base64url (RFC 4648 §5) ------------------------------------------------


def decode_base64url(segment: str) -> bytes:
    """Decode one JWT segment: URL-safe alphabet, padding restored, strict.

    JWT segments omit the ``=`` padding on the wire; the correct number of
    padding chars is restored before decoding. ``validate=True`` rejects
    any stray character (e.g. standard-alphabet ``+``/``/`` or whitespace)
    instead of silently discarding it.
    """
    if not isinstance(segment, str) or not segment:
        raise JwtParseError("JWT segment must be a non-empty string")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.b64decode(
            padded.encode("ascii"), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise JwtParseError(
            "JWT segment is not valid base64url (RFC 4648 §5)"
        ) from exc


# -- Registered-claim helpers -----------------------------------------------


def as_str_list(value: Any) -> tuple[str, ...]:
    """Normalize a claim that may be a string or a list into a tuple."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return ()


def audience_contains(aud: Any, expected: str) -> bool:
    """OIDC Core aud semantics: string (exact) OR array (member)."""
    if isinstance(aud, str):
        return aud == expected
    if isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        return expected in aud
    return False


# -- GCP Workload Identity Pool audience (Prompt 091) ------------------------
#
# The GCP STS token-exchange contract: when a WorkloadIdentityPoolProvider
# has no custom ``allowedAudiences`` list, the OIDC token's ``aud`` claim
# MUST equal the provider's FULL canonical resource name, with or without
# the ``https:`` prefix (IAM REST API, WorkloadIdentityPoolProvider):
#
#     //iam.googleapis.com/projects/{project_number}/locations/global/
#         workloadIdentityPools/{pool_id}/providers/{provider_id}
#
# Resource constraints (projects.locations.workloadIdentityPools.create and
# .providers.create API specs): ``project_number`` is strictly numeric;
# ``pool_id`` / ``provider_id`` are 4–32 chars drawn from ``[a-z0-9-]`` and
# must not begin with ``gcp-``. A pool-level audience (no ``/providers/``
# segment) is unconditionally rejected by STS — trust and attribute mapping
# are attached to the PROVIDER, not the pool. The regex is compiled ONCE at
# module load: zero recompilation latency per verified request.

_WIP_AUDIENCE_RE = re.compile(
    r"^(?:https:)?//iam\.googleapis\.com/projects/\d+"
    r"/locations/global/workloadIdentityPools/"
    r"(?!gcp-)[a-z0-9-]{4,32}"
    r"/providers/(?!gcp-)[a-z0-9-]{4,32}$"
)


def is_wip_audience(aud: Any) -> bool:
    """Pure predicate: is ``aud`` a valid GCP Workload Identity Pool
    PROVIDER resource name?

    Never raises — returns False for non-strings and for any string that
    violates the STS audience schema (wildcards, pool-level paths, path
    traversal, uppercase/underscore IDs, the reserved ``gcp-`` prefix,
    wrong location, plain-``http:`` URLs, trailing segments). The
    fail-closed counterpart :func:`validate_wip_audience` raises a typed
    :class:`JwtValidationError`.
    """
    return isinstance(aud, str) and _WIP_AUDIENCE_RE.match(aud) is not None


def validate_wip_audience(
    claims: Mapping[str, Any],
    *,
    expected_audience: str | None = None,
) -> dict[str, Any]:
    """Validate that the token's ``aud`` is a GCP WIP provider resource path.

    Prompt 091 — the audience half of the Workload Identity Federation
    binding. Fail-closed (raises :class:`JwtValidationError`):

    * ``aud`` present, a string or an array of strings;
    * every audience member matches the STS canonical provider resource
      name (a pool-level audience is rejected, mirroring GCP STS
      behavior);
    * multi-audience tokens MUST carry ``azp`` (OIDC Core hardening) and
      ``azp == expected_audience`` when one is pinned;
    * when `expected_audience` is given it must be a member
      (string-exact or array-membership, :func:`audience_contains`) AND
      itself match the WIP schema — a misconfigured pin is caught here,
      not at STS.

    Returns the claims dict unchanged on success.
    """
    aud = claims.get("aud")
    if aud is None:
        raise JwtValidationError("token missing required 'aud' claim")
    if isinstance(aud, str):
        audiences = (aud,)
    elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        audiences = tuple(aud)
    else:
        raise JwtValidationError(
            f"'aud' claim MUST be a string or an array of strings, "
            f"received {type(aud).__name__}"
        )
    if not audiences:
        raise JwtValidationError("token 'aud' claim is empty")
    for member in audiences:
        if not is_wip_audience(member):
            raise JwtValidationError(
                f"audience {member!r} is not a GCP Workload Identity Pool "
                "provider resource path "
                "(//iam.googleapis.com/projects/.../workloadIdentityPools/"
                ".../providers/...)"
            )
    if len(audiences) > 1:
        azp = claims.get("azp")
        if azp is None:
            raise JwtValidationError(
                "an 'azp' claim is REQUIRED when multiple audiences are "
                "present"
            )
        if expected_audience is not None and azp != expected_audience:
            raise JwtValidationError(
                f"the 'azp' claim ({azp!r}) does not match the expected "
                f"audience {expected_audience!r}"
            )
    if expected_audience is not None:
        # Config sanity FIRST: a misconfigured pin (not a WIP provider
        # resource name) is a deployment error — report it before the
        # membership check so the operator sees the schema violation, not
        # a confusing mismatch.
        if not is_wip_audience(expected_audience):
            raise JwtValidationError(
                f"expected audience {expected_audience!r} is not a valid "
                "GCP Workload Identity Pool provider resource path"
            )
        if not audience_contains(aud, expected_audience):
            raise JwtValidationError(
                f"token audience mismatch: expected {expected_audience!r} "
                f"in {aud!r}"
            )
    return dict(claims)


# -- Attestation-claim extraction (Prompt 085) ------------------------------
#
# The Confidential Space identity claims, with the EXACT paths verified by
# the user research (Google Confidential Space attestation docs + CEL
# policies): ``sub``, ``aud``, ``swname`` are TOP-LEVEL; ``image_digest`` is
# NESTED at ``submods.container.image_digest``; ``instance_id`` is NESTED at
# ``submods.gce.instance_id``. Claim extraction is canonical here so that
# attestation.py and any later phase never hand-roll nested path walking.


def get_nested_claim(claims: Mapping[str, Any], path: str) -> Any:
    """Walk a dotted path (e.g. ``submods.container.image_digest``) through
    nested claim objects.

    Returns None if any intermediate value is missing or is not a JSON
    object — never raises. This is the single canonical nested-claim reader
    for the attestation claims (research: the ``submods`` object carries
    the ``container`` and ``gce`` submodule namespaces).
    """
    current: Any = claims
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def extract_attestation_claims(
    claims: Mapping[str, Any],
) -> dict[str, Any]:
    """Extract the Confidential Space attestation identity claims (Prompt
    085) with their research-verified paths:

    * ``sub``          — top-level OIDC subject (optional in practice; the
      caller decides whether its absence is acceptable).
    * ``aud``          — top-level OIDC audience (string or list).
    * ``swname``       — top-level software name (``CONFIDENTIAL_SPACE``).
    * ``image_digest`` — **NESTED** at ``submods.container.image_digest``
      (NOT top-level — the research: ``assertion.submods.container.
      image_digest`` in Google CEL policies).
    * ``instance_id``  — **NESTED** at ``submods.gce.instance_id`` (the
      research: ``assertion.submods.gce.instance_id`` in Google CEL
      policies; NOT a top-level claim).

    Type violations (a non-string where a string is required) raise
    :class:`JwtValidationError`; absent claims yield None (honest absence —
    the caller, e.g. attestation.py, decides which must be present).
    """
    sub = claims.get("sub")
    aud = claims.get("aud")
    swname = claims.get("swname")
    image_digest = get_nested_claim(claims, "submods.container.image_digest")
    instance_id = get_nested_claim(claims, "submods.gce.instance_id")

    for name, value in (
        ("sub", sub),
        ("swname", swname),
        ("image_digest", image_digest),
        ("instance_id", instance_id),
    ):
        if value is not None and not isinstance(value, str):
            raise JwtValidationError(
                f"claim {name!r} MUST be a string, received "
                f"{type(value).__name__}"
            )

    return {
        "sub": sub,
        "aud": aud,
        "swname": swname,
        "image_digest": image_digest,
        "instance_id": instance_id,
    }


def verify_confidential_space_claims(claims: Any) -> bool:
    """Boolean predicate: is this a Confidential Space attestation token?

    Prompt 086 — implements the Google CEL identity gate
    ``assertion.swname == 'CONFIDENTIAL_SPACE'`` as a pure, never-raising
    predicate. Returns True only when the ``swname`` claim exists, is a
    string, and equals :data:`EXPECTED_SWNAME`. Everything else — a
    missing claim, a non-string value, a different software name — returns
    False (honest rejection; the caller decides the error semantics, e.g.
    attestation.py raises its typed :class:`UntrustedEnvironmentError` on
    this predicate failing).

    NOTE: this is the *identity* half of the access rule. The blueprint's
    full gate also requires the container image digest to match the
    Workload Identity Pool attribute condition (``assertion.submods.
    container.image_digest == var.container_sha256``) — that binding is
    enforced by the attestation engine, which pins the digest format and
    (later phase) the registered digest value.
    """
    if not isinstance(claims, Mapping):
        return False
    swname = claims.get("swname")
    return isinstance(swname, str) and swname == EXPECTED_SWNAME


def validate_numeric_date(
    claims: Mapping[str, Any],
    name: str,
    *,
    required: bool = False,
) -> int | float | None:
    """Return the claim as a number if it is a valid RFC 7519 NumericDate.

    Rejects string-typed dates and — critically — booleans (Python's
    ``bool`` subclasses ``int``, so ``True`` would otherwise pass an
    ``isinstance(int)`` check and become timestamp 1). Raises
    :class:`JwtValidationError` on type violations; missing optional
    claims return None.
    """
    value = claims.get(name)
    if value is None:
        if required:
            raise JwtValidationError(f"token missing required {name!r} claim")
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise JwtValidationError(
            f"claim {name!r} MUST be a JSON number (NumericDate), "
            f"received {type(value).__name__}"
        )
    return value


def validate_expiration(
    claims: Mapping[str, Any],
    *,
    clock_skew: float = DEFAULT_CLOCK_SKEW_S,
    now: float | None = None,
) -> int | float:
    """Validate the ``exp`` (expiration time) claim.

    Prompt 091 — the standalone expiry check: ``exp`` MUST be an RFC 7519
    NumericDate and in the future (beyond ``now - clock_skew``). Raises
    :class:`JwtValidationError` when the claim is missing, non-numeric, or
    the token is expired. Returns the validated ``exp`` value. This is the
    single source of the expiry rule, reused by
    :func:`validate_oidc_claims`.
    """
    now_t = time.time() if now is None else now
    exp = validate_numeric_date(claims, "exp", required=True)
    if now_t - clock_skew >= exp:
        raise JwtValidationError(
            f"token expired (exp={exp}, now={now_t:.0f})"
        )
    return exp


# -- Structural decode ------------------------------------------------------


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a JWT into ``(header, claims)`` — structure only.

    Enforces: exactly three dot-separated segments, valid base64url,
    valid JSON objects for header AND payload, ``alg`` present and not
    ``"none"``, and ``typ == JWT`` when ``typ`` is present. Raises
    :class:`JwtParseError` on any violation.
    """
    if not isinstance(token, str) or not token.strip():
        raise JwtParseError("JWT must be a non-empty string")
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JwtParseError(
            "JWT must contain exactly 3 dot-separated segments "
            f"(got {len(parts)})"
        )
    try:
        header = json.loads(decode_base64url(parts[0]))
        claims = json.loads(decode_base64url(parts[1]))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtParseError(
            "JWT header/payload is not valid JSON"
        ) from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JwtParseError(
            "JWT header and payload must be JSON objects"
        )

    alg = header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none":
        raise JwtParseError(
            "JWT header MUST contain a valid 'alg' (none is rejected)"
        )
    typ = header.get("typ")
    if typ is not None and (not isinstance(typ, str) or typ.upper() != "JWT"):
        raise JwtParseError(
            f"if 'typ' is present it should be 'JWT', got {typ!r}"
        )
    return header, claims


# -- Claim validation (OIDC Core §3.1.3.7) -----------------------------------


def validate_oidc_claims(
    claims: Mapping[str, Any],
    *,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    clock_skew: float = DEFAULT_CLOCK_SKEW_S,
    require_sub: bool = False,
    require_iat: bool = False,
    require_wip_audience: bool = False,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate the OIDC registered claims of a decoded token.

    Returns the claims dict (unchanged) on success; raises
    :class:`JwtValidationError` on any violation. Attestation-specific
    claims are NOT touched here — that is the caller's job.

    * ``iss`` — validated only when `expected_issuer` is given (the
      attestation engine always pins it).
    * ``aud`` — validated only when `expected_audience` is given: string
      exact match or array membership; multi-audience requires
      ``azp == expected_audience``.
    * ``exp`` — REQUIRED NumericDate in the future (within skew).
    * ``iat`` — NumericDate not in the future (within skew); presence
      enforced via `require_iat`.
    * ``nbf`` — optional NumericDate not in the future (within skew).
    * ``sub`` — presence + non-empty string enforced via `require_sub`.
    * ``require_wip_audience`` — when True, ``aud`` must additionally be a
      GCP Workload Identity Pool PROVIDER resource path (Prompt 091): every
      member is validated against the STS canonical schema, and the pinned
      ``expected_audience`` (if any) must itself match the schema.
    """
    now_t = time.time() if now is None else now

    if expected_issuer is not None:
        if claims.get("iss") != expected_issuer:
            raise JwtValidationError(
                f"token issuer is {claims.get('iss')!r}, expected "
                f"{expected_issuer!r}"
            )
    if require_sub:
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise JwtValidationError("token missing required 'sub' claim")

    if expected_audience is not None:
        aud = claims.get("aud")
        if not audience_contains(aud, expected_audience):
            raise JwtValidationError(
                f"token audience mismatch: expected {expected_audience!r} "
                f"in {aud!r}"
            )
        # OIDC Core hardening: multiple audiences MUST carry azp, and azp
        # MUST equal the expected audience (confused-deputy defense).
        if isinstance(aud, list) and len(aud) > 1:
            azp = claims.get("azp")
            if azp is None:
                raise JwtValidationError(
                    "an 'azp' claim is REQUIRED when multiple audiences "
                    "are present"
                )
            if azp != expected_audience:
                raise JwtValidationError(
                    f"the 'azp' claim ({azp!r}) does not match the "
                    f"expected audience {expected_audience!r}"
                )
        elif isinstance(aud, str):
            azp = claims.get("azp")
            if azp is not None and azp != expected_audience:
                raise JwtValidationError(
                    f"the 'azp' claim ({azp!r}) does not match the "
                    f"expected audience {expected_audience!r}"
                )

    if require_wip_audience:
        validate_wip_audience(
            claims, expected_audience=expected_audience
        )

    exp = validate_expiration(
        claims, clock_skew=clock_skew, now=now_t
    )
    iat = validate_numeric_date(claims, "iat", required=require_iat)
    if iat is not None and iat > now_t + clock_skew:
        raise JwtValidationError(
            f"token issued in the future (iat={iat}, now={now_t:.0f}, "
            f"skew={clock_skew})"
        )
    nbf = validate_numeric_date(claims, "nbf")
    if nbf is not None and now_t + clock_skew < nbf:
        raise JwtValidationError(
            f"token is not yet valid (nbf={nbf}, now={now_t:.0f}, "
            f"skew={clock_skew})"
        )

    return dict(claims)


def decode_and_validate(
    token: str,
    *,
    expected_issuer: str | None = None,
    expected_audience: str | None = None,
    clock_skew: float = DEFAULT_CLOCK_SKEW_S,
    require_sub: bool = False,
    require_iat: bool = False,
    require_wip_audience: bool = False,
    now: float | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a JWT and validate its OIDC claims in one step.

    Convenience composing :func:`decode_jwt` + :func:`validate_oidc_claims`;
    returns ``(header, claims)``.
    """
    header, claims = decode_jwt(token)
    validated = validate_oidc_claims(
        claims,
        expected_issuer=expected_issuer,
        expected_audience=expected_audience,
        clock_skew=clock_skew,
        require_sub=require_sub,
        require_iat=require_iat,
        require_wip_audience=require_wip_audience,
        now=now,
    )
    return header, validated


__all__ = [
    "DEFAULT_CLOCK_SKEW_S",
    "EXPECTED_SWNAME",
    "JwtError",
    "JwtParseError",
    "JwtValidationError",
    "as_str_list",
    "audience_contains",
    "decode_and_validate",
    "decode_base64url",
    "decode_jwt",
    "extract_attestation_claims",
    "get_nested_claim",
    "is_wip_audience",
    "validate_expiration",
    "validate_numeric_date",
    "validate_oidc_claims",
    "validate_wip_audience",
    "verify_confidential_space_claims",
]

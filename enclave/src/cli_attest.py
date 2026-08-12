"""cli_attest.py — manual attestation fetch + inspection CLI (Prompt 093).

A zero-dependency (stdlib-only) operations CLI for manually triggering and
inspecting the enclave's TEE hardware attestation. It is a THIN wrapper over
the real engine — :class:`src.crypto.attestation.AttestationEngine` and the
module-level conveniences — which already implement the Confidential Space
contract (POST ``http://localhost/v1/token`` with ``{audience, nonces,
token_type: "OIDC"}``, launcher Unix-socket routing, nonce-echo anti-replay,
audience pinning, swname/image-digest validation, fail-closed typed errors).
The CLI adds the ops ergonomics ONLY; it never reimplements fetch, JWT
parsing, or validation, and it never fabricates a token.

Design (user-pro-verified research + standard ops-CLI practice):

* **argparse, stdlib-only** — the professional choice for internal TEE
  tooling that must run in hardened/minimal images (distroless / slim) where
  every extra package grows the Trusted Computing Base. No click/typer.
* **Five subcommands** mirroring the attestation lifecycle (the nitro-cli /
  Intel Trust Authority CLI pattern)::

      cli_attest.py fetch    fetch + validate the primary vTPM token, print safe measurements
      cli_attest.py raw      EXPLICITLY print the raw vTPM JWT (secrets exposure, on demand)
      cli_attest.py intel    fetch + validate the Intel Trust Authority (TDX) token
      cli_attest.py status   full fallback-flow snapshot (primary + Intel on TDX) + validity
      cli_attest.py proof    generate the combined attestation proof (token + digest + ZK proof)

* **Exit-code contract (fail-closed)**::

      0  success (attestation proven / inspection completed)
      1  operational failure — endpoint unreachable, timeout, missing engine
         wheel. NEVER falls back to a cached or mock token; the caller
         (k8s probe / sidecar) must treat this as "evict the node".
      2  validation failure — the endpoint responded but the token is
         malformed, expired, wrong audience/nonce, or untrusted swname.

* **Secrets handling** — the raw JWT is a privileged bearer token: NEVER
  printed by ``fetch``/``status``/``intel``/``proof`` (only safe derived
  measurements). Only the explicit ``raw`` subcommand emits it.
* **``--json``** — global flag: diagnostics ALWAYS go to stderr; stdout
  carries ONLY valid JSON (``cli_attest.py fetch --json | jq
  .image_digest``). On failure with ``--json``, stdout still carries a
  structured ``{"error": ..., "exit_code": N}`` document.
* **Config** — explicit flags with environment overrides (the same
  variables ``main.py`` honors): ``ENCLAVE_ATTESTATION_ENDPOINT``,
  ``ENCLAVE_INTEL_ATTESTATION_ENDPOINT``, ``ENCLAVE_TEESERVER_SOCKET``.

Run from anywhere (the script bootstraps the ``enclave/`` root on
``sys.path`` so ``import src.*`` resolves regardless of CWD)::

    python enclave/src/cli_attest.py fetch --audience flare-verifiable-rag
    python -m src.cli_attest status --json   # from enclave/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Bootstrap so `import src.*` works whether this is run as a plain script
# (from anywhere) or as `python -m src.cli_attest` from enclave/.
_SRC_ROOT = Path(__file__).resolve().parent.parent  # the enclave/ directory
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from src.crypto.attestation import (  # noqa: E402  (post-bootstrap import)
    ATTESTATION_ENDPOINT,
    DEFAULT_AUDIENCE,
    DEFAULT_TIMEOUT_S,
    INTEL_TOKEN_ENDPOINT,
    TEESERVER_SOCKET,
    AttestationEngine,
    AttestationError,
    AttestationServiceUnavailableError,
    AttestationToken,
    IntelAttestationToken,
)
from src.crypto.jwt_parser import (  # noqa: E402
    verify_confidential_space_claims,
)

# -- Exit-code contract (research + standard ops-CLI practice) -------------

EXIT_OK = 0
EXIT_UNREACHABLE = 1  # operational failure: endpoint down / wheel missing
EXIT_INVALID = 2      # validation failure: token malformed/expired/untrusted


# -- Small output helpers --------------------------------------------------


def _err(message: str) -> None:
    """Diagnostics channel — always stderr (keeps --json stdout pure)."""
    print(f"cli_attest: {message}", file=sys.stderr)


def _emit(payload: Any, *, json_mode: bool) -> None:
    """Write the command result to stdout: pretty JSON in --json mode,
    otherwise a clean human-readable rendering of the same data."""
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return
    _render_human(payload)


def _render_human(payload: Any) -> None:
    # Failures never reach _emit (main()'s except blocks handle them), so
    # this only renders successful command results.
    if isinstance(payload, dict):
        width = max((len(str(k)) for k in payload), default=0)
        for key, value in payload.items():
            print(f"{str(key).upper().ljust(width)}: {_fmt(value)}")
        return
    print(payload)


def _fmt(value: Any) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, default=str)
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if value is None:
        return "(none)"
    return str(value)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _measurements_payload(token: AttestationToken) -> dict[str, Any]:
    """The SAFE derived measurements of the primary token (never the raw
    JWT — secrets rule). Mirrors AttestationToken.get_measurements() plus
    the CEL identity gate for ops visibility."""
    m = token.get_measurements()
    m["confidential_space"] = verify_confidential_space_claims(token.claims)
    return m


def _intel_status(intel: IntelAttestationToken | None) -> dict[str, Any] | None:
    """Shape the ITA token into the status snapshot (same shape main.py's
    /v1/attestation endpoint reports — code reuse)."""
    if intel is None:
        return None
    return {
        "attested": True,
        "issuer": intel.issuer,
        "hwmodel": intel.hwmodel,
        "attester_tcb": list(intel.attester_tcb),
        "policy_ids_matched": list(intel.policy_ids_matched),
        "policy_ids_unmatched": list(intel.policy_ids_unmatched),
        "token_issued_at": (
            intel.issued_at.isoformat() if intel.issued_at else None
        ),
    }


def _status_payload(primary: AttestationToken, intel: IntelAttestationToken | None) -> dict[str, Any]:
    """The full attestation-state snapshot (mirrors AttestationStateResponse)."""
    validity: int | None = None
    if primary.expires_at is not None:
        validity = max(
            0, int((primary.expires_at - _now_utc()).total_seconds())
        )
    return {
        "attested": True,
        "swname": primary.swname,
        "image_digest": primary.image_digest,
        "instance_id": primary.instance_id,
        "hardware": primary.hardware,
        "token_issued_at": (
            primary.issued_at.isoformat() if primary.issued_at else None
        ),
        "token_expires_at": (
            primary.expires_at.isoformat() if primary.expires_at else None
        ),
        "validity_seconds_remaining": validity,
        "confidential_space": verify_confidential_space_claims(primary.claims),
        "intel": _intel_status(intel),
    }


# -- Command implementations (thin wrappers over the real engine) ----------


def _build_engine(args: argparse.Namespace) -> AttestationEngine:
    """Construct the engine honoring flags with env overrides (same env
    variables main.py uses — one source of truth for contact points)."""
    endpoint = (
        args.endpoint
        or os.environ.get("ENCLAVE_ATTESTATION_ENDPOINT", ATTESTATION_ENDPOINT)
    )
    intel_endpoint = (
        args.intel_endpoint
        or os.environ.get(
            "ENCLAVE_INTEL_ATTESTATION_ENDPOINT", INTEL_TOKEN_ENDPOINT
        )
    )
    socket_path = (
        args.socket_path
        or os.environ.get("ENCLAVE_TEESERVER_SOCKET", TEESERVER_SOCKET)
    )
    audience = args.audience or DEFAULT_AUDIENCE
    nonces: list[str] | None = [args.nonce] if args.nonce else None
    return AttestationEngine(
        endpoint=endpoint,
        intel_endpoint=intel_endpoint,
        socket_path=socket_path,
        timeout=args.timeout,
        audience=audience,
        nonces=nonces,
    )


def _run(coro) -> Any:
    """Run one engine coroutine to completion on a fresh event loop.

    The engine's fetch methods are ``async`` (they move the blocking
    urllib/Unix-socket I/O to a worker thread via ``asyncio.to_thread``).
    A CLI command is a single short-lived operation, so one
    ``asyncio.run`` per command is exactly right (no loop-bound state is
    held across commands).
    """
    return asyncio.run(coro)


def _cmd_fetch(args: argparse.Namespace) -> int:
    """fetch — fetch + validate the primary vTPM token, print safe
    measurements. Fail-closed: transport failure -> 1, invalid token -> 2."""
    engine = _build_engine(args)
    token = _run(engine.fetch_token())  # raises typed AttestationError
    _emit(_measurements_payload(token), json_mode=args.json)
    return EXIT_OK


def _cmd_raw(args: argparse.Namespace) -> int:
    """raw — EXPLICIT secret exposure: print the raw vTPM JWT. The only
    subcommand that emits the bearer token (never on by default)."""
    engine = _build_engine(args)
    raw = _run(engine.fetch_vtpm_token())
    if args.json:
        _emit({"jwt": raw}, json_mode=True)
    else:
        print(raw)
    return EXIT_OK


def _cmd_intel(args: argparse.Namespace) -> int:
    """intel — fetch + validate the Intel Trust Authority (TDX) token and
    print its measurements (the independent third-party verifier path)."""
    engine = _build_engine(args)
    token = _run(engine.fetch_intel_attestation())
    _emit(token.get_measurements(), json_mode=args.json)
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    """status — full fallback-flow snapshot: primary + Intel (on TDX) with
    validity. Mirrors GET /v1/attestation so ops sees the same state the
    API serves."""
    engine = _build_engine(args)
    result = _run(engine.fetch_token_with_fallback())
    _emit(_status_payload(result.primary, result.intel), json_mode=args.json)
    return EXIT_OK


def _cmd_proof(args: argparse.Namespace) -> int:
    """proof — generate the combined attestation proof (real Rust engine):
    vTPM token + attested image digest + halo2 ZK proof, bound by the
    recomputable binding hash. Fails closed (exit 1) when the engine wheel
    is not installed or the token cannot be fetched."""
    engine = _build_engine(args)
    proof = _run(engine.generate_attestation_proof(args.document, args.prompt))
    record = proof.to_record()
    record["binding_hash"] = proof.binding_hash
    _emit(record, json_mode=args.json)
    return EXIT_OK


# -- Argparse wiring -------------------------------------------------------


def _common_options() -> argparse.ArgumentParser:
    """The shared option set, attached to the MAIN parser AND every
    subparser (the professional argparse pattern for options that must
    work both before and after the subcommand — the default behaviour
    would reject ``fetch --json`` with "unrecognized arguments")."""
    common = argparse.ArgumentParser(add_help=False)
    # IMPORTANT: every shared option uses default=argparse.SUPPRESS so the
    # subparser's default can never clobber a value the MAIN parser already
    # parsed (the classic argparse subparser bug: a subparser that did not
    # see the flag would otherwise overwrite the main namespace with its
    # default). The effective defaults are applied by _normalize_args after
    # parsing. This makes every flag work BOTH before and after the
    # subcommand (``--json fetch`` and ``fetch --json``).
    common.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit ONLY JSON to stdout (diagnostics stay on stderr)",
    )
    common.add_argument(
        "--endpoint",
        default=argparse.SUPPRESS,
        help=f"vTPM token endpoint (env ENCLAVE_ATTESTATION_ENDPOINT; default {ATTESTATION_ENDPOINT})",
    )
    common.add_argument(
        "--intel-endpoint",
        default=argparse.SUPPRESS,
        help=f"Intel Trust Authority endpoint (env ENCLAVE_INTEL_ATTESTATION_ENDPOINT; default {INTEL_TOKEN_ENDPOINT})",
    )
    common.add_argument(
        "--socket-path",
        default=argparse.SUPPRESS,
        help=f"launcher tee-server Unix socket (env ENCLAVE_TEESERVER_SOCKET; default {TEESERVER_SOCKET})",
    )
    common.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS,
        help=f"request timeout in seconds (default {DEFAULT_TIMEOUT_S})",
    )
    common.add_argument(
        "--audience",
        default=argparse.SUPPRESS,
        help=f"OIDC audience pin (default {DEFAULT_AUDIENCE})",
    )
    common.add_argument(
        "--nonce",
        default=argparse.SUPPRESS,
        help="explicit request nonce (default: fresh CSPRNG nonce per run)",
    )
    return common


def _normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    """Apply the effective defaults for SUPPRESS'd shared options."""
    for name, default in (
        ("json", False),
        ("endpoint", None),
        ("intel_endpoint", None),
        ("socket_path", None),
        ("timeout", DEFAULT_TIMEOUT_S),
        ("audience", None),
        ("nonce", None),
    ):
        if not hasattr(args, name):
            setattr(args, name, default)
    return args


def build_parser() -> argparse.ArgumentParser:
    common = _common_options()
    parser = argparse.ArgumentParser(
        prog="cli_attest",
        parents=[common],
        description=(
            "Manual TEE hardware-attestation fetch + inspection (Confidential "
            "Space vTPM OIDC). Fail-closed: exit 1 = endpoint unreachable / "
            "operational failure, exit 2 = token validation failure."
        ),
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser(
        "fetch",
        parents=[common],
        help="fetch + validate primary vTPM token, print safe measurements",
    )
    p_fetch.set_defaults(func=_cmd_fetch)

    p_raw = sub.add_parser(
        "raw", parents=[common], help="EXPLICIT: print the raw vTPM JWT bearer token"
    )
    p_raw.set_defaults(func=_cmd_raw)

    p_intel = sub.add_parser(
        "intel",
        parents=[common],
        help="fetch + validate the Intel Trust Authority (TDX) token",
    )
    p_intel.set_defaults(func=_cmd_intel)

    p_status = sub.add_parser(
        "status",
        parents=[common],
        help="full fallback-flow attestation snapshot + validity",
    )
    p_status.set_defaults(func=_cmd_status)

    p_proof = sub.add_parser(
        "proof",
        parents=[common],
        help="generate the combined attestation proof (token + digest + ZK proof)",
    )
    p_proof.add_argument(
        "document", help="the document text the proof attests (real engine input)"
    )
    p_proof.add_argument(
        "prompt", help="the prompt text the proof attests (real engine input)"
    )
    p_proof.set_defaults(func=_cmd_proof)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = _normalize_args(parser.parse_args(argv))

    try:
        return int(args.func(args))
    except AttestationServiceUnavailableError as exc:
        # Endpoint unreachable / timed out / empty body — fail CLOSED. Never
        # fall back to a cached or mock token.
        _err(f"CRITICAL: attestation endpoint unreachable (fail-closed): {exc}")
        if args.json:
            print(json.dumps({"error": "attestation_unavailable", "exit_code": EXIT_UNREACHABLE}))
        return EXIT_UNREACHABLE
    except (AttestationError, ValueError) as exc:
        # Endpoint responded but the token failed validation (malformed,
        # expired, audience/nonce mismatch, untrusted swname) — or a bad
        # argument value.
        _err(f"attestation validation failed: {exc}")
        if args.json:
            print(json.dumps({"error": "attestation_invalid", "exit_code": EXIT_INVALID}))
        return EXIT_INVALID
    except RuntimeError as exc:
        # e.g. the indexer_rs engine wheel is not installed (proof path).
        _err(f"operational failure: {exc}")
        if args.json:
            print(json.dumps({"error": "operational_failure", "exit_code": EXIT_UNREACHABLE}))
        return EXIT_UNREACHABLE
    except KeyboardInterrupt:
        _err("interrupted")
        return 130
    except Exception as exc:  # defensive — never an unhandled traceback in ops
        _err(f"unexpected failure: {type(exc).__name__}: {exc}")
        if args.json:
            print(json.dumps({"error": "unexpected_failure", "exit_code": EXIT_UNREACHABLE}))
        return EXIT_UNREACHABLE


if __name__ == "__main__":
    sys.exit(main())

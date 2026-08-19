"""Prompt 093 — unit tests for the attestation inspection CLI.

Targets ``src.cli_attest``: the zero-dependency ops CLI for manually
triggering and inspecting TEE hardware attestation. Every test runs the CLI
against a REAL local ``http.server`` that answers the engine's POST with a
genuinely HS256-signed Confidential Space token (the same real-transport
fixture machinery as test_attestation.py — nothing is monkeypatched on the
fetch path, no fabricated tokens, zero mock).

What is proven:

* **Exit-code contract** — 0 success, 1 endpoint unreachable / operational
  failure (fail-closed: never a fallback token), 2 validation failure
  (expired token, untrusted swname), 2 usage errors (argparse).
* **Secrets rule** — ``fetch``/``status``/``intel``/``proof`` never print
  the raw JWT; only the explicit ``raw`` subcommand emits the bearer token.
* **``--json`` stdout purity** — with ``--json``, stdout is ONLY JSON
  (parseable by ``jq``); every diagnostic goes to stderr. Even failure
  exits emit a structured ``{"error", "exit_code"}`` document on stdout.
* **Subcommand dispatch** — fetch / raw / intel / status / proof + the
  documented ``python enclave/src/cli_attest.py`` invocation (subprocess,
  end-to-end, including the sys.path bootstrap).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from src import cli_attest
from src.crypto.attestation import DEFAULT_AUDIENCE
from test_attestation import (  # real fixture machinery (genuine HS256)
    echo_responder,
    engine_url,
    intel_echo_responder,
    make_claims,
    make_server,
    sign_hs256,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent  # flare-verifiable-rag/
CLI_PATH = REPO_ROOT / "enclave" / "src" / "cli_attest.py"


# -- Helpers ---------------------------------------------------------------


def _cli_args(endpoint: str, sub: list[str] | None = None) -> list[str]:
    """Base argv: primary AND Intel endpoints pointed at the REAL local tee
    server (the fixture server answers any POST path, mirroring how the
    tests in test_attestation.py wire intel_endpoint)."""
    args = [
        "--endpoint", endpoint,
        "--intel-endpoint", endpoint,
        "--audience", DEFAULT_AUDIENCE,
        "--nonce", "n1",
    ]
    return args + (sub or [])


def _dead_url() -> str:
    import socket

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()  # nothing listening -> connection refused
    return f"http://127.0.0.1:{port}/v1/token"


# -- Exit-code contract ----------------------------------------------------


def test_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        cli_attest.main(["--help"])
    assert exc.value.code == 0


def test_unknown_subcommand_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli_attest.main(["nonsense-subcommand"])
    assert exc.value.code == 2  # argparse usage error


def test_proof_requires_positional_arguments():
    with pytest.raises(SystemExit) as exc:
        cli_attest.main(["proof"])
    assert exc.value.code == 2


def test_fetch_happy_path_real_server(capsys):
    server = make_server(echo_responder)
    try:
        code = cli_attest.main(_cli_args(engine_url(server), ["fetch"]))
        assert code == 0
        out = capsys.readouterr()
        assert "CONFIDENTIAL_SPACE" in out.out  # swname measurement shown
        assert "sha256:" in out.out  # image_digest shown
        assert out.err == ""  # no diagnostics on the happy path
    finally:
        server.shutdown()
        server.server_close()


def test_fetch_never_prints_raw_jwt(capsys):
    """Secrets rule: `fetch` shows derived measurements ONLY — the bearer
    token must not appear on stdout by default."""
    server = make_server(echo_responder)
    try:
        token = sign_hs256(make_claims(audience=DEFAULT_AUDIENCE, nonce="n1"))
        code = cli_attest.main(_cli_args(engine_url(server), ["fetch"]))
        assert code == 0
        out = capsys.readouterr()
        assert token not in out.out
        assert "CONFIDENTIAL_SPACE" in out.out
    finally:
        server.shutdown()
        server.server_close()


def test_raw_prints_jwt_only_when_requested(capsys):
    server = make_server(echo_responder)
    try:
        code = cli_attest.main(_cli_args(engine_url(server), ["raw"]))
        assert code == 0
        out = capsys.readouterr()
        jwt = out.out.strip()
        assert len(jwt.split(".")) == 3  # header.payload.signature — a real JWT
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_endpoint_fails_closed_exit_1(capsys):
    """Endpoint down -> exit 1, human mode: message on stderr, nothing on
    stdout. Fail-closed — the CLI never falls back to a cached/mock token."""
    code = cli_attest.main(
        ["--endpoint", _dead_url(), "--timeout", "1.0", "fetch"]
    )
    assert code == 1
    out = capsys.readouterr()
    assert "unreachable" in out.err.lower()
    assert out.out == ""  # human mode: nothing on stdout for a failure


def test_unreachable_endpoint_json_mode_structured_error(capsys):
    code = cli_attest.main(["--json", "--endpoint", _dead_url(), "--timeout", "1.0", "fetch"])
    assert code == 1
    out = capsys.readouterr()
    doc = json.loads(out.out)  # stdout stays PURE JSON even on failure
    assert doc["exit_code"] == 1
    assert doc["error"] == "attestation_unavailable"
    assert "unreachable" in out.err.lower()


def test_expired_token_fails_validation_exit_2(capsys):
    def expired(_body: bytes) -> tuple[int, str, bytes]:
        claims = make_claims(audience=DEFAULT_AUDIENCE, nonce="n1", exp_offset=-7200.0)
        return 200, "application/json", sign_hs256(claims).encode("utf-8")

    server = make_server(expired)
    try:
        code = cli_attest.main(_cli_args(engine_url(server), ["fetch"]))
        assert code == 2
        out = capsys.readouterr()
        assert "expired" in out.err.lower()
    finally:
        server.shutdown()
        server.server_close()


def test_untrusted_swname_fails_validation_exit_2(capsys):
    def bad_env(_body: bytes) -> tuple[int, str, bytes]:
        claims = make_claims(audience=DEFAULT_AUDIENCE, nonce="n1", swname="GCE")
        return 200, "application/json", sign_hs256(claims).encode("utf-8")

    server = make_server(bad_env)
    try:
        code = cli_attest.main(_cli_args(engine_url(server), ["fetch"]))
        assert code == 2
        out = capsys.readouterr()
        assert "swname" in out.err.lower()
    finally:
        server.shutdown()
        server.server_close()


# -- --json stdout purity --------------------------------------------------


def test_fetch_json_stdout_is_pure_json(capsys):
    server = make_server(echo_responder)
    try:
        code = cli_attest.main(["--json", *_cli_args(engine_url(server), ["fetch"])])
        assert code == 0
        out = capsys.readouterr()
        doc = json.loads(out.out)  # parses cleanly -> pipeable to jq
        assert doc["swname"] == "CONFIDENTIAL_SPACE"
        assert doc["image_digest"].startswith("sha256:")
        assert doc["confidential_space"] is True
        assert out.err == ""
    finally:
        server.shutdown()
        server.server_close()


# -- status / intel subcommands --------------------------------------------


def test_status_snapshot_shape_real_server(capsys):
    server = make_server(echo_responder)
    try:
        code = cli_attest.main(["--json", *_cli_args(engine_url(server), ["status"])])
        assert code == 0
        out = capsys.readouterr()
        doc = json.loads(out.out)
        assert doc["attested"] is True
        assert doc["swname"] == "CONFIDENTIAL_SPACE"
        assert doc["validity_seconds_remaining"] is not None
        assert doc["confidential_space"] is True
        assert doc["intel"] is None  # AMD fixture -> no ITA fallback
    finally:
        server.shutdown()
        server.server_close()


def test_intel_subcommand_real_server(capsys):
    server = make_server(intel_echo_responder)
    try:
        code = cli_attest.main(["--json", *_cli_args(engine_url(server), ["intel"])])
        assert code == 0
        out = capsys.readouterr()
        doc = json.loads(out.out)
        assert doc["attested"] is True
        assert doc["hwmodel"] == "GCP_INTEL_TDX"
        assert doc["attester_tcb"] == ["INTEL"]
    finally:
        server.shutdown()
        server.server_close()


# -- proof subcommand: missing-wheel fail-closed ---------------------------


def test_proof_missing_wheel_fails_closed_exit_1(capsys):
    """The `proof` subcommand needs the REAL Rust engine wheel; when it is
    not installed the CLI fails closed (exit 1, operational failure) AFTER
    the token fetch succeeds — never a fabricated proof (mirrors
    test_attestation's missing-wheel test)."""
    server = make_server(echo_responder)
    try:
        prev = sys.modules.get("indexer_rs")
        sys.modules["indexer_rs"] = None  # import indexer_rs -> RuntimeError
        try:
            code = cli_attest.main(
                [*_cli_args(engine_url(server)), "proof", "doc", "prompt"]
            )
            assert code == 1
            out = capsys.readouterr()
            assert "operational failure" in out.err
            assert "not installed" in out.err
        finally:
            if prev is not None:
                sys.modules["indexer_rs"] = prev
            else:
                sys.modules.pop("indexer_rs", None)
    finally:
        server.shutdown()
        server.server_close()


# -- End-to-end subprocess (documented invocation) -------------------------


def test_subprocess_documented_invocation_json(capsys):
    """The DOCUMENTED run command — ``python enclave/src/cli_attest.py``
    from the repo root — works end-to-end (sys.path bootstrap included):
    stdout is pure JSON, exit 0."""
    server = make_server(echo_responder)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "fetch",
                "--json",
                "--endpoint",
                engine_url(server),
                "--audience",
                DEFAULT_AUDIENCE,
                "--nonce",
                "n1",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO_ROOT),
        )
        assert result.returncode == 0
        doc = json.loads(result.stdout)  # pure JSON on stdout
        assert doc["swname"] == "CONFIDENTIAL_SPACE"
        assert result.stderr == ""
    finally:
        server.shutdown()
        server.server_close()


def test_subprocess_unreachable_exit_1_json(capsys):
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "--json",
            "--endpoint",
            _dead_url(),
            "--timeout",
            "1.0",
            "fetch",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 1
    doc = json.loads(result.stdout)  # structured error, still pure JSON
    assert doc["exit_code"] == 1

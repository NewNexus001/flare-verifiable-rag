#!/usr/bin/env bash
# scripts/bazel_test_all.sh — run every hermetic Bazel test (Prompt 310).
#
# Phase 16: `bazel test //...` executes the Rust, Solidity and TypeScript
# test suites inside Bazel's sandbox — the same hermetic engine CI runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Resolve the Bazel launcher: full installations ship `bazel`, bazelisk-only
# setups expose the same binary as `bazelisk`. Both invoke Bazel 8.4.1 via
# .bazelversion at the workspace root.
BZ="$(command -v bazel || command -v bazelisk || true)"
if [ -z "$BZ" ]; then
  echo "[bazel_test_all] ERROR: neither 'bazel' nor 'bazelisk' is on PATH" >&2
  exit 1
fi

echo "[bazel_test_all] workspace: $ROOT"
echo "[bazel_test_all] launcher: $BZ"
echo "[bazel_test_all] bazel version: $($BZ --version)"

echo "[bazel_test_all] running: bazel test //... (hermetic, sandboxed)"
$BZ test //... --test_output=errors

echo "[bazel_test_all] PASS: all hermetic test suites are green"

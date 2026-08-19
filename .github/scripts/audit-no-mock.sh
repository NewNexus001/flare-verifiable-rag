#!/usr/bin/env bash
# .github/scripts/audit-no-mock.sh
#
# PHASE 11-12 NO-MOCK AUDIT (enclave_grpc — Tokio gRPC core + IETF RATS EAT)
# Mechanical scan of the Rust gRPC enclave core for anything fake:
#   1. Mock/stub markers (placeholder, dummy, fake, stub, TODO-live)
#   2. Fake private keys (quoted 64-hex secrets / PEM blocks)
#   3. Stubbed endpoints (handlers returning hardcoded canned payloads)
#   4. Fake RPC endpoints (hosts outside the canonical allowlist)
#   5. Hardcoded on-chain addresses (must resolve via registry)
#   6. Hardcoded attestation tokens / fake measurements
# Exit 0 = clean, 1 = violation. CI-gate ready.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Scan scope: the Phase 11-12 crate. Everything else is audited by
# audit-data-integrity.sh.
SCOPE='enclave/enclave_grpc'
EXT='--include=*.rs --include=*.proto --include=*.toml'
EXCLDIR='--exclude-dir=target'

# Whitelisted paths inside the scope (test-only hardware emulator shim is the
# documented design for hosts lacking TDX silicon — it generates REAL EAT
# tokens through the real eat_builder, it is not fake data).
filter_out() {
  grep -v 'tests/mock_tdx_device.rs'
}

fail() {
  echo "FAIL: $1"
  shift
  [ "$#" -gt 0 ] && printf '%s\n' "$@"
  exit 1
}

echo "== Phase 11-12 No-Mock Audit (scope: $SCOPE) =="

# 1) Mock/stub markers in production code (tests/ is legitimate test code)
hits=$(grep -rniE 'placeholder|wireframe|lorem ipsum|dummy|fake data|sample data|demo data|not implemented|coming soon|stub' "$SCOPE/src" "$SCOPE/proto" "$SCOPE/build.rs" "$SCOPE/Cargo.toml" $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "mock/stub markers found" "$hits"
echo "OK: no mock/stub markers in production code."

# 2) Fake private keys: quoted 64-hex secrets or PEM blocks
hits=$(grep -rniE "[\"']0x[0-9a-fA-F]{64}|BEGIN [A-Z ]*PRIVATE KEY" "$SCOPE" $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "potential private key material found" "$hits"
echo "OK: no private key material."

# 3) Stubbed endpoints: handlers that return hardcoded canned payloads
#    (hex-encoded string literals returned as if they were real data)
hits=$(grep -rnE 'return (Ok|Err)\([^)]*"[0-9a-fA-F]{32,}"' "$SCOPE/src" $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "stubbed endpoint returning canned payload" "$hits"
echo "OK: no stubbed endpoints."

# 4) Fake RPC endpoints: RPC-like URLs whose host is outside the allowlist
#    (canonical: flare.network / flare-coston2.quiknode.pro / localhost /
#    127.0.0.1 / cloud.google.com — documented in REAL-DATA-SOURCES.md)
hits=$(grep -rniE '(https?|wss)://[^ ]*(rpc|infura|alchemy|quiknode|publicnode|ankr|moralis|chainstack|getblock)' "$SCOPE" $EXT $EXCLDIR 2>/dev/null \
  | filter_out \
  | grep -vE 'flare\.network|flare-coston2\.quiknode\.pro|localhost|127\.0\.0\.1|0\.0\.0\.0|cloud\.google\.com' || true)
[ -n "$hits" ] && fail "RPC endpoint outside canonical allowlist found" "$hits"
echo "OK: no fake/unknown RPC endpoints."

# 5) Hardcoded on-chain addresses in logic (defense in depth)
hits=$(grep -rnE '0x[0-9a-fA-F]{40}\b' "$SCOPE/src" $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "hardcoded on-chain addresses (use FlareContractRegistry)" "$hits"
echo "OK: no hardcoded on-chain addresses."

# 6) Hardcoded attestation tokens / fake PCR measurements in production code
hits=$(grep -rniE 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|"PCR_[0-9]+"\s*:\s*"[0-9a-f]{64}"|RTMR[0-3]\s*=\s*"[0-9a-f]{64}"' "$SCOPE/src" $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "hardcoded attestation token / fake measurement found" "$hits"
echo "OK: no hardcoded attestation tokens."

echo "== PHASE 11-12 AUDIT PASSED: enclave_grpc contains only real, production code =="

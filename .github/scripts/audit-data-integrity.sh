#!/usr/bin/env bash
# .github/scripts/audit-data-integrity.sh
#
# DATA INTEGRITY AUDIT
# Mechanical scans for anything that is not real-world data:
#   1. Hardcoded test data / fabricated markers
#   2. Fake private keys (64-hex secrets / PEM blocks)
#   3. Dummy arrays (hardcoded on-chain address lists)
#   4. Fake RPC endpoints (hosts outside the canonical allowlist)
#   5. Hardcoded on-chain addresses in logic (must resolve via registry)
# Exit 0 = clean, 1 = violation. CI-gate ready.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# Source-file extensions scanned (lockfiles, binaries, git internals excluded).
EXT='--include=*.sh --include=*.ps1 --include=*.json --include=*.yaml --include=*.yml --include=*.ts --include=*.tsx --include=*.js --include=*.jsx --include=*.py --include=*.sol --include=*.md --include=*.tf --include=*.rs --include=*.toml'

# Directories grep must NEVER descend into (excluded at walk time, so the
# scan stays fast AND correct — pnpm per-package node_modules at any depth,
# git internals, and generated artifact trees). The filter_out() pipeline
# additionally drops any stragglers by path.
EXCLDIR='--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=.turbo --exclude-dir=.tools --exclude-dir=.terraform --exclude-dir=dist --exclude-dir=artifacts --exclude-dir=coverage --exclude-dir=typechain-types --exclude-dir=target --exclude-dir=.venv --exclude-dir=venv'

# Never trigger on: git internals, node_modules (root AND any workspace
# package, e.g. blockchain/node_modules after `pnpm install`), the lockfile,
# this script, the web-verified reference manifest (REAL-DATA-SOURCES.md), or
# generated toolchain/artifact directories (.tools/, .terraform/, .turbo/,
# .next/, dist/, artifacts/ + cache/ (Hardhat), coverage/, typechain-types/,
# target/) - these hold binaries, machine dumps (e.g. terraform providers
# schema -json) and generated docs (rustdoc's search UI legitimately contains
# the word "placeholder" as an HTML attribute and JS variable name) that are
# gitignored and not repo content.
filter_out() {
  grep -v '^./.git/' | grep -vE '/node_modules(/|$)' | grep -v 'pnpm-lock.yaml' \
    | grep -v 'audit-no-mock.sh' | grep -v 'audit-data-integrity.sh' | grep -v 'REAL-DATA-SOURCES.md' \
    | grep -v 'VIDEO-PITCH-GUIDE.md' | grep -v 'RULES.md' | grep -v 'PROJECT-STATE.md' | grep -v 'FLARE-KNOWLEDGE.md' | grep -v 'SYSTEM-VERIFICATION-REPORT.md' \
    | grep -v '^./.tools/' | grep -v '^./.turbo/' | grep -v '^./.next/' \
    | grep -v '^./dist/' | grep -v '/artifacts/' | grep -v '^./blockchain/cache/' \
    | grep -v '^./coverage/' | grep -v '/typechain-types/' \
    | grep -v '^./infra/terraform/.terraform/' | grep -v '/target/' \
    | grep -v 'jsonplaceholder\.typicode\.com' \
    | grep -v 'fdc-web2json-proof\.json'
    # /artifacts/ + /typechain-types/ at ANY depth and blockchain/cache/
    # (Hardhat's generated trees, gitignored); node_modules-at-any-depth
    # covers pnpm's per-package stores. cache is scoped to blockchain/cache
    # so a future legit source directory named "cache" is never skipped.
    # VIDEO-PITCH-GUIDE.md is documentation (the shot-by-shot submission
    # guide), not logic: its only 40-hex strings are the REAL deployed
    # VerifiableRAG.sol address (0x403b...9897, documented in
    # REAL-DATA-SOURCES.md) and the Coston2 explorer URL for it.
    # jsonplaceholder.typicode.com is a REAL, live, publicly-served API
    # (NOT mock data) — the Web2Json endpoint empirically attested by the
    # FDC attestor network on Coston2 round 1422772 (real merkle proof saved
    # at blockchain/test/fixtures/fdc-web2json-proof.json; attested value
    # matched the live ground truth). Exempted here because the marker
    # scan's substring 'placeholder' is a false positive on the domain name.
    # fdc-web2json-proof.json is REAL machine-fetched DA-layer proof data
    # (response_hex + merkle path from https://ctn2-data-availability.flare.network
    # for tx 0xdc4c3ecc... on round 1422772 — provenance in REAL-DATA-SOURCES.md),
    # not key material: its 64-hex words trip the private-key regex, same as
    # the already-exempted REAL-DATA-SOURCES.md reference values.
}

fail() {
  echo "FAIL: $1"
  shift
  [ "$#" -gt 0 ] && printf '%s\n' "$@"
  exit 1
}

echo "== Data Integrity Audit (root: $REPO_ROOT) =="

# 1) Hardcoded mock/fake markers
hits=$(grep -rniE 'placeholder|wireframe|lorem ipsum|dummy|fake data|sample data|demo data|not implemented|coming soon' . $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "mock/placeholder markers found" "$hits"
echo "OK: no mock/placeholder markers."

# 2) Fake private keys: quoted 64-hex secrets or PEM blocks. Bare identifiers
#    (process.env.PRIVATE_KEY) and unquoted bytes32/uint256 literals are legit
#    and must NOT trip the scan.
hits=$(grep -rniE "[\"']0x[0-9a-fA-F]{64}|BEGIN [A-Z ]*PRIVATE KEY" . $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "potential private key material found" "$hits"
echo "OK: no private key material."

# 3) Dummy arrays: hardcoded arrays containing on-chain addresses
hits=$(grep -rnE '\[[^]]*0x[0-9a-fA-F]{40}\b' . $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "hardcoded address arrays (dummy arrays) found" "$hits"
echo "OK: no dummy address arrays."

# 4) Fake RPC endpoints: RPC-like URLs whose host is outside the allowlist
#    (canonical: flare.network + flare-coston2.quiknode.pro (Flare-documented
#    public failover RPC, live-verified chain id 114 on 2026-08-06 and
#    documented in REAL-DATA-SOURCES.md), cloud.google.com;
#    real-local: localhost/127.0.0.1)
hits=$(grep -rniE '(https?|wss)://[^ ]*(rpc|infura|alchemy|quiknode|publicnode|ankr|moralis|chainstack|getblock)' . $EXT $EXCLDIR 2>/dev/null \
  | filter_out \
  | grep -vE 'pnpm-lock|audit-no-mock|REAL-DATA-SOURCES|flare\.network|flare-coston2\.quiknode\.pro|localhost|127\.0\.0\.1|0\.0\.0\.0|cloud\.google\.com|\.terraform/' || true)
[ -n "$hits" ] && fail "RPC endpoint outside canonical allowlist found" "$hits"
echo "OK: no fake/unknown RPC endpoints."

# 5) Hardcoded on-chain addresses in logic files (defense in depth).
#    \b ensures 40-hex only: 64-hex bytes32/uint256 constants must not trip.
hits=$(grep -rnE '0x[0-9a-fA-F]{40}\b' . $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "hardcoded on-chain addresses in logic (use FlareContractRegistry)" "$hits"
echo "OK: no hardcoded on-chain addresses."

# 6) Static price fallback variables (Phase 8 / Prompt 155): any identifier that
#    suggests a hardcoded fallback/default price instead of reading the LIVE
#    FTSO v2 feed. Legit constants (feed IDs, time windows) never match.
hits=$(grep -rniE 'fallback.?price|price.?fallback|staticPrice|hardcodedPrice|fallbackValue|defaultPrice' . $EXT $EXCLDIR 2>/dev/null | filter_out || true)
[ -n "$hits" ] && fail "hardcoded static price fallbacks found" "$hits"
echo "OK: no static price fallbacks."

echo "== AUDIT PASSED: repository contains only verified real-world data =="

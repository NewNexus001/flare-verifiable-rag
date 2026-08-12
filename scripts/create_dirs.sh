#!/usr/bin/env bash
# scripts/create_dirs.sh
#
# Idempotent monorepo directory scaffold for flare-verifiable-rag.
# Safe to re-run at any time: `mkdir -p` never errors on existing directories.
#
# Usage: bash scripts/create_dirs.sh   (from anywhere in the repo)
set -euo pipefail

# Resolve the repo root as the parent of scripts/, so this works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

DIRS=(
  ".github/workflows"
  "infra/terraform"
  "blockchain/contracts/interfaces"
  "blockchain/scripts"
  "enclave/src/crypto"
  "enclave/src/rag_engine"
  "enclave/src/flare_client"
  "frontend/src/app"
  "frontend/src/components"
)

echo "Creating monorepo directory tree under: $REPO_ROOT"
for d in "${DIRS[@]}"; do
  mkdir -p "$d"
  echo "  ok  $d"
done

echo
echo "Verified tree (all directories):"
find . -type d -not -path './.git*' | sort

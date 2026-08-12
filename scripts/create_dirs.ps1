# scripts/create_dirs.ps1
#
# Idempotent monorepo directory scaffold for flare-verifiable-rag (PowerShell).
# Equivalent to scripts/create_dirs.sh. Safe to re-run at any time:
# New-Item -Force never errors on existing directories.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/create_dirs.ps1
$ErrorActionPreference = "Stop"

# Resolve the repo root as the parent of scripts/, so this works from any cwd.
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$Dirs = @(
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

Write-Host "Creating monorepo directory tree under: $RepoRoot"
foreach ($d in $Dirs) {
  New-Item -ItemType Directory -Path $d -Force | Out-Null
  Write-Host "  ok  $d"
}

# Verification: every declared directory must exist as a container.
# Only the 9 declared paths are checked, so the `.git*` glob trap from the
# bash `find` version (which swallowed `.github*`) cannot occur here.
Write-Host ""
Write-Host "Verification (non-empty directory creation):"
$missing = 0
foreach ($d in $Dirs) {
  if (Test-Path -Path $d -PathType Container) {
    Write-Host "  EXISTS  $d"
  } else {
    Write-Host "  MISSING $d"
    $missing++
  }
}

if ($missing -gt 0) {
  Write-Host "FAILED: $missing of $($Dirs.Count) directories missing." -ForegroundColor Red
  exit 1
} else {
  Write-Host "PASSED: all $($Dirs.Count) directories present."
}

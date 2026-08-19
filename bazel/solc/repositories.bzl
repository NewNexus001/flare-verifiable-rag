"""Hermetic solc 0.8.24 toolchain (Phase 16, Prompt 304).

The maintained Solidity ruleset (rules_sol) pins solc at 0.8.19, but this
repo's contracts are pragma ^0.8.24 and compiled with `--evm-version cancun`
(see hardhat.config.ts). The professional fix is a minimal purpose-built
rule that pins the EXACT solc 0.8.24 release binary per platform, verified
by sha256 — the same binary Hardhat ships, consumed hermetically inside
Bazel.

Binaries come from the official Solidity release server
(https://binaries.soliditylang.org) — the canonical, signed source.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# sha256 of solc-windows-amd64-v0.8.24+commit.e11b9ed9.exe (verified by
# downloading the official release and running `sha256sum`).
_SOLC_VERSIONS = {
    "linux_amd64": {
        "url": "https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9",
        "sha256": "fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f",
    },
    "windows_amd64": {
        "url": "https://binaries.soliditylang.org/windows-amd64/solc-windows-amd64-v0.8.24+commit.e11b9ed9.exe",
        "sha256": "580ee56b61bbcaad953117e1e4a0874d90e6af5cb4ce4359571d7da25f6620e9",
    },
}

def solc_repositories():
    """Fetch the pinned solc 0.8.24 binary for every supported platform."""
    for name, data in _SOLC_VERSIONS.items():
        http_file(
            name = "solc_0_8_24_%s" % name,
            url = data["url"],
            sha256 = data["sha256"],
            executable = True,
        )

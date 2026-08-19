"""solc_contract — hermetic Solidity compilation (Phase 16, Prompt 304).

Compiles a set of .sol sources with the pinned solc 0.8.24 binary
(see repositories.bzl) using `--combined-json abi,bin,hashes` and
`--evm-version cancun` — the exact settings hardhat.config.ts uses, so the
Bazel artifact is byte-identical in intent to the Hardhat build. Imports
resolve via `--base-path` and `--include-path` so node_modules libraries
(@openzeppelin) work the same way they do under Hardhat.

Outputs (DefaultInfo):
  combined.json  — ABI + bytecode + function hashes for every contract
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

def _solc_contract_impl(ctx):
    solc = ctx.toolchains["//bazel/solc:toolchain_type"].solc
    combined = ctx.actions.declare_file("combined.json")

    args = ctx.actions.args()
    args.add("--combined-json", "abi,bin,hashes")
    args.add("--evm-version", "cancun")
    args.add("--optimize")
    args.add("--base-path", ".")
    if ctx.attr.include_paths:
        for p in ctx.attr.include_paths:
            args.add("--include-path", p)
    # node_modules is a pnpm symlink farm; solc would refuse to follow it
    # out of the allowed dirs. Bazel's sandbox already guarantees
    # reproducibility, so relax solc's own directory check (the same
    # approach rules_sol takes).
    args.add("--allow-paths", "/")
    args.add_all(ctx.files.srcs)
    args.add("-o", combined.dirname)

    ctx.actions.run(
        executable = solc,
        arguments = [args],
        inputs = depset(ctx.files.srcs, transitive = [
            d[DefaultInfo].files
            for d in ctx.attr.deps
        ]),
        outputs = [combined],
        mnemonic = "Solc",
        progress_message = "solc %{output} (0.8.24, cancun)",
    )

    return [
        DefaultInfo(
            files = depset([combined]),
        ),
    ]

solc_contract = rule(
    implementation = _solc_contract_impl,
    attrs = {
        "srcs": attr.label_list(
            allow_files = [".sol"],
            mandatory = True,
        ),
        "deps": attr.label_list(
            default = [],
            doc = "Other solc_contract / filegroup targets providing importable .sol files",
        ),
        "include_paths": attr.string_list(
            default = [],
            doc = "Directories searched for bare imports (e.g. node_modules)",
        ),
    },
    toolchains = ["//bazel/solc:toolchain_type"],
)

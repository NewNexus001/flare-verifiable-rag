"""solc_toolchain — carries the pinned solc binary for the toolchain type."""

SolcInfo = provider(
    doc = "How to invoke the pinned solc 0.8.24 binary.",
    fields = {
        "solc": "Executable file of the solc binary",
    },
)

def _solc_toolchain_impl(ctx):
    solc = ctx.file.solc
    return [
        platform_common.ToolchainInfo(solc = solc),
    ]

solc_toolchain = rule(
    implementation = _solc_toolchain_impl,
    attrs = {
        "solc": attr.label(
            allow_single_file = True,
            mandatory = True,
            executable = True,
            cfg = "exec",
        ),
    },
)

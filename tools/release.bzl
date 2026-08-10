"""Rule assembling the gVisor release binaries in their installed layout."""

# SIDECARS maps each sidecar binary target to the filename that runsc expects
# to find under the `gvisor-bin/` directory next to its own binary.
SIDECARS = {
    "//runsc/checkpointgofer:checkpointgofer_binary": "checkpointgofer",
    "//runsc/cmd/metricserver:runsc-metric-server": "runsc-metric-server",
    "//runsc/cmd/sentry:gvisor_sentry": "gvisor_sentry",
    "//runsc/prewarmer:gvisor-sentry-prewarmer": "gvisor-sentry-prewarmer",
}

def _single_file(target):
    files = target[DefaultInfo].files.to_list()
    if len(files) != 1:
        fail("expected exactly one file in %s, got %d" % (target.label, len(files)))
    return files[0]

def _release_files_impl(ctx):
    outputs = []
    inputs = []
    commands = []

    # Top-level binaries
    for target in ctx.attr.bins:
        src = _single_file(target)
        out = ctx.actions.declare_file("%s/%s" % (ctx.label.name, src.basename))
        inputs.append(src)
        outputs.append(out)
        commands.append('cp -f "%s" "%s"' % (src.path, out.path))

    # Sidecar binaries
    for target, name in ctx.attr.sidecars.items():
        src = _single_file(target)
        out = ctx.actions.declare_file("%s/gvisor-bin/%s" % (ctx.label.name, name))
        inputs.append(src)
        outputs.append(out)
        commands.append('mkdir -p "$(dirname "%s")" && cp -f "%s" "%s"' % (out.path, src.path, out.path))

    ctx.actions.run_shell(
        inputs = inputs,
        outputs = outputs,
        command = "\n".join(commands),
        mnemonic = "ReleaseFiles",
    )

    runfiles = ctx.runfiles(files = outputs)
    return [DefaultInfo(
        files = depset(outputs),
        default_runfiles = runfiles,
        data_runfiles = runfiles,
    )]

release_files = rule(
    implementation = _release_files_impl,
    attrs = {
        "bins": attr.label_list(
            doc = "Binaries placed at the top level of the layout.",
            allow_files = True,
            mandatory = True,
        ),
        "sidecars": attr.label_keyed_string_dict(
            doc = "Binaries placed under gvisor-bin/, keyed by target with " +
                  "the in-directory filename as value.",
            allow_files = True,
            mandatory = True,
        ),
    },
    doc = "Assembles release binaries in the layout they are installed in: " +
          "each of `bins` at the top level and `sidecars` under a " +
          "`gvisor-bin/` directory.",
)

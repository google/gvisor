"""Rule assembling the gVisor release binaries in their installed layout."""

# SIDECARS maps each sidecar binary target to the filename that runsc expects
# to find under the `gvisor-bin/` directory next to its own binary.
SIDECARS = {
    "//runsc/checkpointgofer:checkpointgofer_binary": "checkpointgofer",
    "//runsc/cmd/metricserver:runsc-metric-server": "runsc-metric-server",
}

def _single_file(target):
    files = target[DefaultInfo].files.to_list()
    if len(files) != 1:
        fail("expected exactly one file in %s, got %d" % (target.label, len(files)))
    return files[0]

def _release_files_impl(ctx):
    outputs = []

    # Top-level binaries
    for target in ctx.attr.bins:
        src = _single_file(target)
        out = ctx.actions.declare_file("%s/%s" % (ctx.label.name, src.basename))
        ctx.actions.run_shell(
            inputs = [src],
            outputs = [out],
            command = 'cp -f "$1" "$2"',
            arguments = [src.path, out.path],
            mnemonic = "ReleaseFile",
        )
        outputs.append(out)

    # Sidecar binaries
    gvisor_bin = ctx.actions.declare_directory("%s/gvisor-bin" % ctx.label.name)
    sidecar_files = []
    commands = ['mkdir -p "%s"' % (gvisor_bin.path,)]
    for target, name in ctx.attr.sidecars.items():
        src = _single_file(target)
        sidecar_files.append(src)
        commands.append('cp -f "%s" "%s/%s"' % (src.path, gvisor_bin.path, name))
    ctx.actions.run_shell(
        inputs = sidecar_files,
        outputs = [gvisor_bin],
        command = "\n".join(commands),
        mnemonic = "ReleaseSidecars",
    )
    outputs.append(gvisor_bin)

    return [DefaultInfo(files = depset(outputs))]

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

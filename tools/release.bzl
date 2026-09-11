"""Rules assembling the gVisor release binaries in their installed layout."""

load("//tools:defs.bzl", "pkg_tar")

# FLAVORS are the instrumentation flavors of gVisor binaries.
FLAVORS = [
    "default",
    "coverage",
    "race",
    "race-coverage",
]

# RUNSC maps each flavor to the runsc binary target for it.
RUNSC = {
    "default": "//runsc",
    "coverage": "//runsc:runsc_coverage",
    "race": "//runsc:runsc-race",
    "race-coverage": "//runsc:runsc_race_coverage",
}

# SENTRY_SIDECARS maps the filename of each sidecar binary that runs the Sentry
# (the gVisor kernel) to the set of binary targets for each flavor.
SENTRY_SIDECARS = {
    "gvisor_sentry": {
        "default": "//runsc/cmd/sentry:gvisor_sentry",
        "coverage": "//runsc/cmd/sentry:gvisor_sentry_coverage",
        "race": "//runsc/cmd/sentry:gvisor_sentry-race",
        "race-coverage": "//runsc/cmd/sentry:gvisor_sentry_race_coverage",
    },
}

# OTHER_SIDECARS maps each sidecar binary target that does not run the Sentry
# to the filename that runsc expects to find under the `gvisor-bin/` directory
# next to its own binary.
OTHER_SIDECARS = {
    "//runsc/checkpointgofer:checkpointgofer_binary": "checkpointgofer",
    "//runsc/cmd/metricserver:runsc-metric-server": "runsc-metric-server",
    "//runsc/prewarmer:gvisor-sentry-prewarmer": "gvisor-sentry-prewarmer",
}

def sidecars(flavor):
    """Returns the sidecar binaries of the given flavor.

    Args:
      flavor: one of FLAVORS.

    Returns:
      A dict mapping each sidecar binary target to the filename that runsc
      expects to find under the `gvisor-bin/` directory next to its own binary.
    """
    if flavor not in FLAVORS:
        fail("unknown flavor %r, must be one of %r" % (flavor, FLAVORS))
    result = dict(OTHER_SIDECARS)
    for name, targets in SENTRY_SIDECARS.items():
        result[targets[flavor]] = name
    return result

# SIDECARS maps each sidecar binary target to the filename that runsc expects
# to find under the `gvisor-bin/` directory next to its own binary.
SIDECARS = sidecars("default")

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

def instrumented_release_tars(name, flavor, bins = [], visibility = None):
    """Defines release tarballs of gVisor built with the given instrumentation flavor.

    Defines `<name>-tar-bz2` and `<name>-tar-zstd` targets.

    Args:
      name: prefix of the tarball target names and of the tarball file names.
      flavor: one of FLAVORS.
      bins: additional top-level binaries, e.g. the containerd shim.
      visibility: visibility of the tarball targets.
    """
    runsc = RUNSC[flavor]
    gvisor_bin = name + "-gvisor-bin"
    pkg_tar(
        name = gvisor_bin,
        files = sidecars(flavor),
        mode = "0755",
        package_dir = "gvisor-bin",
    )
    for extension, compressor in (("tar.bz2", None), ("tar.zstd", "//tools/zstd:compressor")):
        pkg_tar(
            name = "%s-%s" % (name, extension.replace(".", "-")),
            srcs = bins,
            compressor = compressor,
            extension = extension,
            files = {runsc: "runsc"},
            mode = "0755",
            package_file_name = "%s.%s" % (name, extension),
            visibility = visibility,
            deps = [":" + gvisor_bin],
        )

"""Rules assembling the gVisor release binaries in their installed layout."""

load("//tools:defs.bzl", "COPY_FILE_TOOLCHAINS", "copy_file_action", "cov_available", "tar")

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
    "//runsc/cmd/netgofer:runsc-netgofer": "runsc-netgofer",
    "//runsc/fdparking:fdparking_binary": "runsc-fd-parking",
    "//runsc/prewarmer:prewarmer_binary": "gvisor-sentry-prewarmer",
    "//runsc/procumounter:procumounter_binary": "gvisor-proc-umounter",
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

# RELEASE_RUNSC and RELEASE_SIDECARS are the runsc binary and the sidecars of
# the flavor matching the build configuration: race under --config=race,
# default otherwise.
RELEASE_RUNSC = select({
    "//tools:gotsan": RUNSC["race"],
    "//conditions:default": RUNSC["default"],
})

RELEASE_SIDECARS = select({
    "//tools:gotsan": sidecars("race"),
    "//conditions:default": sidecars("default"),
})

def _single_file(target):
    files = target[DefaultInfo].files.to_list()
    if len(files) != 1:
        fail("expected exactly one file in %s, got %d" % (target.label, len(files)))
    return files[0]

def _release_files_impl(ctx):
    layout = []
    for target in ctx.attr.bins:
        src = _single_file(target)
        layout.append((src, src.basename))
    layout.append((_single_file(ctx.attr.runsc), "runsc"))
    for target, name in ctx.attr.sidecars.items():
        layout.append((_single_file(target), "gvisor-bin/" + name))

    outputs = []
    for src, path in layout:
        out = ctx.actions.declare_file("%s/%s" % (ctx.label.name, path))
        copy_file_action(ctx, src, out)
        outputs.append(out)

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
        "runsc": attr.label(
            doc = "Binary placed at the top level of the layout as `runsc`, " +
                  "whatever its own filename (e.g. `runsc-race`).",
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
          "`runsc` and each of `bins` at the top level and `sidecars` under a " +
          "`gvisor-bin/` directory.",
    toolchains = COPY_FILE_TOOLCHAINS,
)

def release_tars(name, flavor, bins, basename = None, visibility = None):
    """Builds the two downloadable release archives for an instrumentation flavor.

    Args:
      name: Prefix of the two Bazel target names.
      flavor: One of FLAVORS.
      bins: Additional top-level binary labels mapped to installed filenames.
      basename: Filename prefix of the downloads. Defaults to name.
      visibility: Visibility of the archive targets.
    """
    if not cov_available and "coverage" in flavor:
        return
    files = {RUNSC[flavor]: "runsc"}
    files.update(bins)
    files.update({src: "gvisor-bin/" + path for src, path in sidecars(flavor).items()})

    # A fixed timestamp, numeric root ownership and executable modes make the
    # archive independent of the worker that built it.
    mtree = [
        "/set uid=0 gid=0 time=946684800 mode=0755",
        "./gvisor-bin type=dir",
    ] + [
        "./%s type=file content=$(location %s)" % (path, src)
        for src, path in files.items()
    ]
    for suffix, compress, compressor in (
        ("bz2", "bzip2", None),
        ("zstd", "zstd", "//tools/zstd:compressor"),
    ):
        tar(
            name = name + "-tar-" + suffix,
            srcs = files.keys(),
            # mtree uses full paths prefixed with "./". The publisher extracts
            # the member named exactly "runsc" from each archive.
            args = ["-s", ",^[.]/,,", "--uname", "", "--gname", ""],
            compress = compress,
            compressor = compressor,
            mtree = mtree,
            out = (basename or name) + ".tar." + suffix,
            visibility = visibility,
        )

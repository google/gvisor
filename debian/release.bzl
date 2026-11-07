"""Build the downloadable release archives from their installed filenames."""

load("@tar.bzl//tar:tar.bzl", "tar")
load("//tools:defs.bzl", "cov_available")
load("//tools:release.bzl", "RUNSC", "sidecars")

def _archive_alias_impl(ctx):
    archive = ctx.file.archive
    ctx.actions.symlink(output = ctx.outputs.out, target_file = archive)
    return [DefaultInfo(
        files = depset([archive]),
        runfiles = ctx.runfiles(files = [archive, ctx.outputs.out]),
    )]

_archive_alias = rule(
    implementation = _archive_alias_impl,
    attrs = {
        "archive": attr.label(allow_single_file = True, mandatory = True),
        "out": attr.output(mandatory = True),
    },
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

    # Match the existing release's portable UTC timestamp, numeric ownership
    # and executable modes. Each content path names a declared binary input.
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
        public = name + "-tar-" + suffix
        writer = public + "_archive"
        tar(
            name = writer,
            srcs = files.keys(),
            # mtree uses full paths prefixed with "./". The publisher extracts
            # the member named exactly "runsc" from each archive.
            args = ["-s", ",^[.]/,,", "--uname", "", "--gname", ""],
            compress = compress,
            compressor = compressor,
            mtree = mtree,
            out = (basename or name) + ".tar." + suffix,
        )

        # pkg_tar exposes the download in DefaultInfo.files and both paths in
        # runfiles. Existing Bazel callers can also request the target-named link.
        _archive_alias(
            name = public,
            archive = ":" + writer,
            out = public + ".tar." + suffix,
            visibility = visibility,
        )

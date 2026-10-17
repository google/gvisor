"""Repository rule that extracts the data archive of a Debian package."""

def _deb_data_impl(rctx):
    rctx.extract(archive = rctx.path(rctx.attr.data))
    rctx.file("BUILD.bazel", rctx.attr.build_file_content)

deb_data = repository_rule(
    implementation = _deb_data_impl,
    attrs = {
        "build_file_content": attr.string(
            doc = "Content of the BUILD file of the repository.",
            mandatory = True,
        ),
        "data": attr.label(
            doc = "The data archive (e.g. data.tar.xz) of a Debian package, " +
                  "as unpacked by http_archive(type = \"deb\").",
            allow_single_file = True,
            mandatory = True,
        ),
    },
    doc = """Extracts the files installed by a Debian package.""",
)

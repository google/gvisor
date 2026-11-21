"""Gives source files of a Go library."""

load("//tools/bazeldefs:go.bzl", "go_source_files")

def _go_library_srcs_impl(ctx):
    by_name = {f.basename: f for f in go_source_files(ctx.attr.library)}
    files = []
    for name in ctx.attr.srcs:
        if name not in by_name:
            fail("%s has no source file %s" % (ctx.attr.library.label, name))
        files.append(by_name[name])
    return [DefaultInfo(files = depset(files))]

go_library_srcs = rule(
    implementation = _go_library_srcs_impl,
    doc = "Gives the source files of a Go library that have the names in `srcs`, in the same order.",
    attrs = {
        "library": attr.label(mandatory = True, doc = "The Go library."),
        "srcs": attr.string_list(mandatory = True, doc = "The file names of the source files."),
    },
)

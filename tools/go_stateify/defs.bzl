"""Stateify is a tool for generating state wrappers for Go types.

The recommended way to use this tool is to use the go_library rule defined in
the tools directory.

load("//tools:defs.bzl", "go_library")

go_library(
    name = "foo",
    srcs = ["foo.go"],
    stateify_imports = ["extra/go/import/for/generated/package"],
)

Under the hood, the go_stateify rule is used to generate a file that will
appear in a Go target; the output file should appear explicitly in a srcs list.
For example:

load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "foo_state",
    srcs = ["foo.go"],
    imports = ["extra/go/import/for/generated/package"],
    out = "foo_state.go",
    package = "foo",
)

go_library(
    name = "foo",
    srcs = [
        "foo.go",
        "foo_state.go",
    ],
    deps = [
        "//pkg/state",
    ],
)
"""

GO_STATEIFY_DEPS = [
    "//pkg/state",
]

def _go_stateify_impl(ctx):
    """Implementation for the stateify tool."""
    output = ctx.outputs.out

    # Run the stateify command.
    args = ["-output=%s" % output.path]
    args += ["-pkg=%s" % ctx.attr.package]
    if ctx.attr._statepkg:
        args += ["-statepkg=%s" % ctx.attr._statepkg]
    if ctx.attr.imports:
        args += ["-imports=%s" % ",".join(ctx.attr.imports)]
    args += ["--"]
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]
    ctx.actions.run(
        inputs = ctx.files.srcs,
        outputs = [output],
        mnemonic = "GoStateify",
        progress_message = "Generating state library %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

go_stateify = rule(
    implementation = _go_stateify_impl,
    doc = "Generates save and restore logic from a set of Go files.",
    attrs = {
        "srcs": attr.label_list(
            doc = """
The input source files. These files should include all structs in the package
that need to be saved.
""",
            mandatory = True,
            allow_files = True,
        ),
        "imports": attr.string_list(
            doc = """
An optional list of extra non-aliased, Go-style absolute import paths required
for statified types.
""",
            mandatory = False,
        ),
        "package": attr.string(
            doc = "The package name for the input sources.",
            mandatory = True,
        ),
        "out": attr.output(
            doc = """
The name of the generated file output. This must not conflict with any other
files and must be added to the srcs of the relevant go_library.
""",
            mandatory = True,
        ),
        "_tool": attr.label(
            executable = True,
            cfg = "host",
            default = Label("//tools/go_stateify:stateify"),
        ),
        "_statepkg": attr.string(default = "gvisor.dev/gvisor/pkg/state"),
    },
)

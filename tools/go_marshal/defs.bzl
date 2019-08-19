"""Marshal is a tool for generating marshalling interfaces for Go types.

The recommended way to use this tool is to use the go_library rule defined in
the tools directory.

load("//tools:defs.bzl", "go_library")

go_library(
    name = "foo",
    srcs = ["foo.go"],
    marshal_imports = ["extra/go/import/for/generated/package"],
)

Under the hood, the go_marshal rule is used to generate a file that will
appear in a Go target; the output file should appear explicitly in a srcs list.
For example:

load("//tools/go_marshal:defs.bzl", "go_marshal")

go_marshal(
    name = "foo_abi",
    srcs = ["foo.go"],
    imports = ["extra/go/import/for/generated/package"],
    out = "foo_abi.go",
    package = "foo",
)

go_library(
    name = "foo",
    srcs = [
        "foo.go",
        "foo_abi.go",
    ],
    deps = [
       "//tools/go_marshal:marshal",
       "//pkg/sentry/platform/safecopy",
       "//pkg/sentry/usermem",
    ],
)
"""

GO_MARSHAL_DEPS = [
    "//tools/go_marshal/marshal",
    "//pkg/sentry/platform/safecopy",
    "//pkg/sentry/usermem",
]

GO_MARSHAL_TEST_DEPS = [
    "//tools/go_marshal/analysis",
]

def _go_marshal_impl(ctx):
    """Execute the go_marshal tool."""
    output = ctx.outputs.lib
    output_test = ctx.outputs.test
    (build_dir, _, _) = ctx.build_file_path.rpartition("/BUILD")

    decl = "/".join(["gvisor.dev/gvisor", build_dir])

    # Run the marshal command.
    args = ["-output=%s" % output.path]
    args += ["-pkg=%s" % ctx.attr.package]
    args += ["-output_test=%s" % output_test.path]
    args += ["-declarationPkg=%s" % decl]

    if ctx.attr.debug:
        args += ["-debug"]

    args += ["--"]
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]
    ctx.actions.run(
        inputs = ctx.files.srcs,
        outputs = [output, output_test],
        mnemonic = "GoMarshal",
        progress_message = "go_marshal: %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

go_marshal = rule(
    implementation = _go_marshal_impl,
    doc = "Generates ABI serialization code from a set of Go files.",
    attrs = {
        "srcs": attr.label_list(
            doc = """
The input source files. These files should have some structs
declarations opting into marshalilng with '// +marshal'.""",
            mandatory = True,
            allow_files = True,
        ),
        "libname": attr.string(
            doc = "Name of the BUILD library containing the target for codegen.",
            mandatory = True,
        ),
        "imports": attr.string_list(
            doc = "Optional list of extra go-style absolute import paths.",
            mandatory = False,
        ),
        "package": attr.string(
            doc = """
            Name of the go package containing the types for which to generate
            code.""",
            mandatory = True,
        ),
        "debug": attr.bool(
            doc = "enable debugging output from the go_marshal tool",
        ),
        "_tool": attr.label(
            executable = True,
            cfg = "host",
            default = Label("//tools/go_marshal:go_marshal"),
        ),
    },
    outputs = {
        "lib": "%{name}_unsafe.go",
        "test": "%{name}_test.go",
    },
)

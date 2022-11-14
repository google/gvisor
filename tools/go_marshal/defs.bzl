"""Marshal is a tool for generating marshalling interfaces for Go types."""

def _go_marshal_impl(ctx):
    """Execute the go_marshal tool."""
    output = ctx.outputs.lib
    output_test = ctx.outputs.test
    output_test_unconditional = ctx.outputs.test_unconditional

    # Run the marshal command.
    args = ["-output=%s" % output.path]
    args.append("-pkg=%s" % ctx.attr.package)
    args.append("-output_test=%s" % output_test.path)
    args.append("-output_test_unconditional=%s" % output_test_unconditional.path)

    if ctx.attr.debug:
        args += ["-debug"]

    args += ["--"]
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]
    ctx.actions.run(
        inputs = ctx.files.srcs,
        outputs = [output, output_test, output_test_unconditional],
        mnemonic = "GoMarshal",
        progress_message = "go_marshal: %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

# Generates save and restore logic from a set of Go files.
#
# Args:
#   name: the name of the rule.
#   srcs: the input source files. These files should include all structs in the
#         package that need to be saved.
#   imports: an optional list of extra, non-aliased, Go-style absolute import
#            paths.
#   out: the name of the generated file output. This must not conflict with any
#        other files and must be added to the srcs of the relevant go_library.
#   package: the package name for the input sources.
go_marshal = rule(
    implementation = _go_marshal_impl,
    attrs = {
        "srcs": attr.label_list(mandatory = True, allow_files = True),
        "imports": attr.string_list(mandatory = False),
        "package": attr.string(mandatory = True),
        "debug": attr.bool(doc = "enable debugging output from the go_marshal tool"),
        "_tool": attr.label(executable = True, cfg = "exec", default = Label("//tools/go_marshal:go_marshal")),
    },
    outputs = {
        "lib": "%{name}_unsafe.go",
        "test": "%{name}_test.go",
        "test_unconditional": "%{name}_unconditional_test.go",
    },
)

# marshal_deps are the dependencies requied by generated code.
marshal_deps = [
    "//pkg/gohacks",
    "//pkg/hostarch",
    "//pkg/marshal",
]

# marshal_test_deps are required by test targets.
marshal_test_deps = [
    "//tools/go_marshal/analysis",
]

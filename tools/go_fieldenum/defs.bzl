"""The go_fieldenum target infers Field, Fields, and FieldSet types for each
struct in an input source file marked +fieldenum.
"""

def _go_fieldenum_impl(ctx):
    output = ctx.outputs.out

    args = ["-pkg=%s" % ctx.attr.package, "-out=%s" % output.path]
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]

    ctx.actions.run(
        inputs = ctx.files.srcs,
        outputs = [output],
        mnemonic = "GoFieldenum",
        progress_message = "Generating Go field enumerators %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

go_fieldenum = rule(
    implementation = _go_fieldenum_impl,
    attrs = {
        "srcs": attr.label_list(doc = "input source files", mandatory = True, allow_files = True),
        "package": attr.string(doc = "the package for the generated source file", mandatory = True),
        "out": attr.output(doc = "output file", mandatory = True),
        "_tool": attr.label(executable = True, cfg = "exec", default = Label("//tools/go_fieldenum:fieldenum")),
    },
)

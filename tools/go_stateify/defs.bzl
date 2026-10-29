"""Stateify is a tool for generating state wrappers for Go types."""

load("@bazel_skylib//lib:paths.bzl", "paths")
load("//tools/bazeldefs:go.bzl", "go_context", "go_rule")

def _go_stateify_impl(ctx):
    """Implementation for the stateify tool."""
    go_ctx = go_context(ctx)
    output = ctx.outputs.out

    tools_path = paths.join(ctx.label.name + "_tools")

    # Use a symlink to the `go` binary to avoid exposing undeclared dependencies
    # on other binaries in the same directory in the toolchain.
    go_symlink = ctx.actions.declare_file(paths.join(tools_path, "go"))
    ctx.actions.symlink(
        output = go_symlink,
        target_file = go_ctx.go,
        is_executable = True,
    )

    args = ["-go=%s" % go_symlink.path, "-output=%s" % output.path]
    args.append("-fullpkg=%s" % ctx.attr.package)
    if ctx.attr._statepkg:
        args.append("-statepkg=%s" % ctx.attr._statepkg)
    if ctx.attr.imports:
        args.append("-imports=%s" % ",".join(ctx.attr.imports))
    args.append("--")
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files.to_list()]
    ctx.actions.run(
        inputs = ctx.files.srcs,
        tools = [go_symlink, go_ctx.runfiles],
        env = go_ctx.env,
        outputs = [output],
        mnemonic = "GoStateify",
        progress_message = "Generating state library %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

go_stateify = go_rule(
    rule,
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
            doc = "The fully qualified package name for the input sources.",
            mandatory = True,
        ),
        "out": attr.output(
            doc = "Name of the generator output file.",
            mandatory = True,
        ),
        "_tool": attr.label(
            executable = True,
            cfg = "exec",
            default = Label("//tools/go_stateify:stateify"),
        ),
        "_statepkg": attr.string(default = "gvisor.dev/gvisor/pkg/state"),
    },
)

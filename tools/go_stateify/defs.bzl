"""Stateify is a tool for generating state wrappers for Go types.

The go_stateify rule is used to generate a file that will appear in a Go
target; the output file should appear explicitly in a srcs list. For example:

go_stateify(
    name = "foo_state",
    srcs = ["foo.go"],
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

load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library", _go_test = "go_test")

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
    if ctx.attr.explicit:
        args += ["-explicit=true"]
    args += ["--"]
    for src in ctx.attr.srcs:
        args += [f.path for f in src.files]
    ctx.actions.run(
        inputs = ctx.files.srcs,
        outputs = [output],
        mnemonic = "GoStateify",
        progress_message = "Generating state library %s" % ctx.label,
        arguments = args,
        executable = ctx.executable._tool,
    )

# Generates save and restore logic from a set of Go files.
#
# Args:
#   name: the name of the rule.
#   srcs: the input source files. These files should include all structs in the package that need to be saved.
#   imports: an optional list of extra non-aliased, Go-style absolute import paths.
#   out: the name of the generated file output. This must not conflict with any other files and must be added to the srcs of the relevant go_library.
#   package: the package name for the input sources.
#   explicit: only generate for types explicitly annotated as savable.
go_stateify = rule(
    implementation = _go_stateify_impl,
    attrs = {
        "srcs": attr.label_list(mandatory = True, allow_files = True),
        "imports": attr.string_list(mandatory = False),
        "package": attr.string(mandatory = True),
        "out": attr.output(mandatory = True),
        "explicit": attr.bool(default = False),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_stateify:stateify")),
        "_statepkg": attr.string(default = "gvisor.googlesource.com/gvisor/pkg/state"),
    },
)

def go_library(name, srcs, deps = [], imports = [], **kwargs):
    """wraps the standard go_library and does stateification."""
    if "encode_unsafe.go" not in srcs and (name + "_state_autogen.go") not in srcs:
        # Only do stateification for non-state packages without manual autogen.
        go_stateify(
            name = name + "_state_autogen",
            srcs = [src for src in srcs if src.endswith(".go")],
            imports = imports,
            package = name,
            out = name + "_state_autogen.go",
            explicit = True,
        )
        all_srcs = srcs + [name + "_state_autogen.go"]
        if "//pkg/state" not in deps:
            all_deps = deps + ["//pkg/state"]
        else:
            all_deps = deps
    else:
        all_deps = deps
        all_srcs = srcs
    _go_library(
        name = name,
        srcs = all_srcs,
        deps = all_deps,
        **kwargs
    )

def go_test(**kwargs):
    """Wraps the standard go_test."""
    _go_test(
        **kwargs
    )

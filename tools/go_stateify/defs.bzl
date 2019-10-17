"""Stateify is a tool for generating state wrappers for Go types.

The recommended way is to use the go_library rule defined below with mostly
identical configuration as the native go_library rule.

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "foo",
    srcs = ["foo.go"],
)

Under the hood, the go_stateify rule is used to generate a file that will
appear in a Go target; the output file should appear explicitly in a srcs list.
For example (the above is still the preferred way):

load("//tools/go_stateify:defs.bzl", "go_stateify")

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

load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library")

def _go_stateify_impl(ctx):
    """Implementation for the stateify tool."""
    output = ctx.outputs.out

    # Run the stateify command.
    args = ["-output=%s" % output.path]
    args += ["-pkg=%s" % ctx.attr.package]
    args += ["-arch=%s" % ctx.attr.arch]
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
        "arch": attr.string(
            doc = "Target platform.",
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

def go_library(name, srcs, deps = [], imports = [], **kwargs):
    """Standard go_library wrapped which generates state source files.

    Args:
      name: the name of the go_library rule.
      srcs: sources of the go_library. Each will be processed for stateify
            annotations.
      deps: dependencies for the go_library.
      imports: an optional list of extra non-aliased, Go-style absolute import
               paths required for stateified types.
      **kwargs: passed to go_library.
    """
    if "encode_unsafe.go" not in srcs and (name + "_state_autogen.go") not in srcs:
        # Only do stateification for non-state packages without manual autogen.
        go_stateify(
            name = name + "_state_autogen",
            srcs = [src for src in srcs if src.endswith(".go")],
            imports = imports,
            package = name,
            arch = select({
                   "@bazel_tools//src/conditions:linux_aarch64": "arm64",
                   "//conditions:default": "amd64",
            }),
            out = name + "_state_autogen.go",
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

"""Marshal is a tool for generating marshalling interfaces for Go types.

The recommended way is to use the go_library rule defined below with mostly
identical configuration as the native go_library rule.

load("//tools/go_marshal:defs.bzl", "go_library")

go_library(
    name = "foo",
    srcs = ["foo.go"],
)

Under the hood, the go_marshal rule is used to generate a file that will
appear in a Go target; the output file should appear explicitly in a srcs list.
For example (the above is still the preferred way):

load("//tools/go_marshal:defs.bzl", "go_marshal")

go_marshal(
    name = "foo_abi",
    srcs = ["foo.go"],
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

load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library", _go_test = "go_test")

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
        "libname": attr.string(mandatory = True),
        "imports": attr.string_list(mandatory = False),
        "package": attr.string(mandatory = True),
        "debug": attr.bool(doc = "enable debugging output from the go_marshal tool"),
        "_tool": attr.label(executable = True, cfg = "host", default = Label("//tools/go_marshal:go_marshal")),
    },
    outputs = {
        "lib": "%{name}_unsafe.go",
        "test": "%{name}_test.go",
    },
)

def go_library(name, srcs, deps = [], imports = [], debug = False, **kwargs):
    """wraps the standard go_library and does mashalling interface generation.

    Args:
      name: Same as native go_library.
      srcs: Same as native go_library.
      deps: Same as native go_library.
      imports: Extra import paths to pass to the go_marshal tool.
      debug: Enables debugging output from the go_marshal tool.
      **kwargs: Remaining args to pass to the native go_library rule unmodified.
    """
    go_marshal(
        name = name + "_abi_autogen",
        libname = name,
        srcs = [src for src in srcs if src.endswith(".go")],
        debug = debug,
        imports = imports,
        package = name,
    )

    extra_deps = [
        "//tools/go_marshal/marshal",
        "//pkg/sentry/platform/safecopy",
        "//pkg/sentry/usermem",
    ]

    all_srcs = srcs + [name + "_abi_autogen_unsafe.go"]
    all_deps = deps + []  #  + extra_deps

    for extra in extra_deps:
        if extra not in deps:
            all_deps.append(extra)

    _go_library(
        name = name,
        srcs = all_srcs,
        deps = all_deps,
        **kwargs
    )

    # Don't pass importpath arg to go_test.
    kwargs.pop("importpath", "")

    _go_test(
        name = name + "_abi_autogen_test",
        srcs = [name + "_abi_autogen_test.go"],
        # Generated test has a fixed set of dependencies since we generate these
        # tests. They should only depend on the library generated above, and the
        # Marshallable interface.
        deps = [
            ":" + name,
            "//tools/go_marshal/analysis",
        ],
        **kwargs
    )

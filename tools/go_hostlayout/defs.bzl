"""Defines go_host_layout_struct_test to generate host layout struct tests."""

load("//tools/bazeldefs:go.bzl", "go_importpath")

def _generate_hostlayout_impl(ctx):
    args = ctx.actions.args()
    args.add("-package", ctx.attr.library.label.name)
    args.add("-importpath", go_importpath(ctx.attr.library))
    args.add("-out", ctx.outputs.out)
    args.add_all(ctx.files.srcs)
    ctx.actions.run(
        executable = ctx.executable._generator,
        arguments = [args],
        inputs = ctx.files.srcs,
        outputs = [ctx.outputs.out],
        mnemonic = "GoHostLayout",
    )

_generate_hostlayout = rule(
    implementation = _generate_hostlayout_impl,
    attrs = {
        "library": attr.label(mandatory = True),
        "out": attr.output(mandatory = True),
        "srcs": attr.label_list(allow_files = [".go"]),
        "_generator": attr.label(
            default = "//tools/go_hostlayout:hostlayoutgen",
            executable = True,
            cfg = "exec",
        ),
    },
)

def go_host_layout_struct_test(go_test_rule_func, name, srcs, library, **kwargs):
    """Checks that all structs in the given source file have _ structs.HostLayout as their first field.

    Args:
      go_test_rule_func: the go_test rule function to use.
      name: the name of the test.
      srcs: the source files to check.
      library: the library that the source files belong to.
      **kwargs: standard arguments.
    """
    gen_file = name + "_generated.go"

    _generate_hostlayout(
        name = name + "_gen",
        srcs = srcs,
        library = library,
        out = gen_file,
    )

    go_test_rule_func(
        name = name,
        srcs = [gen_file],
        deps = [
            library,
            "//tools/go_hostlayout/hostlayoutcheck",
        ],
        **kwargs
    )

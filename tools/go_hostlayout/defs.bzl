"""Defines go_host_layout_struct_test to generate host layout struct tests."""

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

    native.genrule(
        name = name + "_gen",
        srcs = srcs + [library],
        outs = [gen_file],
        tools = ["//tools/go_hostlayout:hostlayoutgen"],
        cmd = "$(location //tools/go_hostlayout:hostlayoutgen) -package " + library.replace(":", "/") + " -out $@ " + " ".join(["$(location %s)" % src for src in srcs]) + " -- $(locations " + library + ")",
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

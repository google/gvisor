"""Defines go_host_layout_struct_test to generate host layout struct tests."""

def go_host_layout_struct_test(go_test_rule_func, generate_hostlayout, name, srcs, library, **kwargs):
    """Checks that all structs in the given source file have _ structs.HostLayout as their first field.

    Args:
      go_test_rule_func: the go_test rule function to use.
      generate_hostlayout: the rule that generates the test source.
      name: the name of the test.
      srcs: the source files to check.
      library: the library that the source files belong to.
      **kwargs: standard arguments.
    """
    gen_file = name + "_generated.go"

    generate_hostlayout(
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

"""Extends the native go_library rule with gvisor tool support.

This build rule wraps around the native go_library rule to add tools support
when building gvisor source.

Currently, the following tools are supported:
- go_marshal: Generates marshalling code for ABI structs.
- go_stateify: Generates code for saving and restoring go types.

For more information about these tools, see the appropriate tool's directory.
"""

load("//tools/go_marshal:defs.bzl", "GO_MARSHAL_DEPS", "GO_MARSHAL_TEST_DEPS", "go_marshal")
load("//tools/go_stateify:defs.bzl", "GO_STATEIFY_DEPS", "go_stateify")
load("@io_bazel_rules_go//go:def.bzl", _go_library = "go_library", _go_test = "go_test")

def go_library(name, srcs, deps = [], marshal = False, stateify = True, marshal_imports = [], stateify_imports = [], debug = False, **kwargs):
    """Wrapper around the native go_library with gvisor tools support.

    Args:
      name: Same as native go_library.
      srcs: Same as native go_library.
      deps: Same as native go_library.
      marshal: Perform go_marshal pass on this library.
      stateify: Perform go_marshal pass on this library.
      marshal_imports: Extra import paths to pass to the go_marshal tool.
      stateify_imports: Extra import paths to pass to the go_stateify tool.
      debug: Enables debugging output from tools that support it.
      **kwargs: Remaining args to pass to the native go_library rule unmodified.
    """
    all_srcs = srcs + []  # Mutable copy of srcs.
    all_deps = deps + []  # Mutable copy of deps.

    # Expand go_marshal rules.
    if marshal and name + "_abi_autogen_unsafe.go" not in srcs:
        go_marshal(
            name = name + "_abi_autogen",
            libname = name,
            srcs = [src for src in srcs if src.endswith(".go")],
            imports = marshal_imports,
            package = name,
            debug = debug,
        )
        all_srcs.append(name + "_abi_autogen_unsafe.go")

        for extra in GO_MARSHAL_DEPS:
            if extra not in all_deps:
                all_deps.append(extra)

        # Don't pass importpath arg to go_test.
        test_kwargs = dict(kwargs)  # Copy kwargs.
        test_kwargs.pop("importpath", "")

        _go_test(
            name = name + "_abi_autogen_test",
            srcs = [name + "_abi_autogen_test.go"],
            deps = [":" + name] + GO_MARSHAL_TEST_DEPS,
            **test_kwargs
        )

    # Expand go_stateify rules.
    if stateify and "encode_unsafe.go" not in srcs and (name + "_state_autogen.go") not in srcs:
        # Only do stateification for non-state packages without manual autogen.
        go_stateify(
            name = name + "_state_autogen",
            srcs = [src for src in srcs if src.endswith(".go")],
            imports = stateify_imports,
            package = name,
            out = name + "_state_autogen.go",
        )
        all_srcs.append(name + "_state_autogen.go")

        for extra in GO_STATEIFY_DEPS:
            if extra not in all_deps:
                all_deps.append(extra)

    # Call the native go_library, with any potentially generated source files
    # included.
    _go_library(
        name = name,
        srcs = all_srcs,
        deps = all_deps,
        **kwargs
    )

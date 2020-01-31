"""Wrappers for common build rules.

These wrappers apply common BUILD configurations (e.g., proto_library
automagically creating cc_ and go_ proto targets) and act as a single point of
change for Google-internal and bazel-compatible rules.
"""

load("//tools/go_stateify:defs.bzl", "go_stateify")
load("//tools/go_marshal:defs.bzl", "go_marshal", "marshal_deps", "marshal_test_deps")
load("//tools/build:defs.bzl", _cc_binary = "cc_binary", _cc_flags_supplier = "cc_flags_supplier", _cc_library = "cc_library", _cc_proto_library = "cc_proto_library", _cc_test = "cc_test", _cc_toolchain = "cc_toolchain", _container_image = "container_image", _default_installer = "default_installer", _default_net_util = "default_net_util", _go_binary = "go_binary", _go_embed_data = "go_embed_data", _go_image = "go_image", _go_library = "go_library", _go_proto_library = "go_proto_library", _go_test = "go_test", _go_tool_library = "go_tool_library", _gtest = "gtest", _loopback = "loopback", _pkg_deb = "pkg_deb", _pkg_tar = "pkg_tar", _proto_library = "proto_library", _py_binary = "py_binary", _py_library = "py_library", _py_requirement = "py_requirement", _py_test = "py_test", _select_arch = "select_arch", _select_system = "select_system")

# Delegate directly.
cc_binary = _cc_binary
cc_library = _cc_library
cc_test = _cc_test
cc_toolchain = _cc_toolchain
cc_flags_supplier = _cc_flags_supplier
container_image = _container_image
go_embed_data = _go_embed_data
go_image = _go_image
go_test = _go_test
go_tool_library = _go_tool_library
gtest = _gtest
pkg_deb = _pkg_deb
pkg_tar = _pkg_tar
py_library = _py_library
py_binary = _py_binary
py_test = _py_test
py_requirement = _py_requirement
select_arch = _select_arch
select_system = _select_system
loopback = _loopback
default_installer = _default_installer
default_net_util = _default_net_util

def go_binary(name, **kwargs):
    """Wraps the standard go_binary.

    Args:
      name: the rule name.
      **kwargs: standard go_binary arguments.
    """
    _go_binary(
        name = name,
        **kwargs
    )

def go_library(name, srcs, deps = [], imports = [], stateify = True, marshal = False, **kwargs):
    """Wraps the standard go_library and does stateification and marshalling.

    The recommended way is to use this rule with mostly identical configuration as the native
    go_library rule.

    These definitions provide additional flags (stateify, marshal) that can be used
    with the generators to automatically supplement the library code.

    load("//tools:defs.bzl", "go_library")

    go_library(
        name = "foo",
        srcs = ["foo.go"],
    )

    Args:
      name: the rule name.
      srcs: the library sources.
      deps: the library dependencies.
      imports: imports required for stateify.
      stateify: whether statify is enabled (default: true).
      marshal: whether marshal is enabled (default: false).
      **kwargs: standard go_library arguments.
    """
    if stateify:
        # Only do stateification for non-state packages without manual autogen.
        go_stateify(
            name = name + "_state_autogen",
            srcs = [src for src in srcs if src.endswith(".go")],
            imports = imports,
            package = name,
            arch = select_arch(),
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
    if marshal:
        go_marshal(
            name = name + "_abi_autogen",
            srcs = [src for src in srcs if src.endswith(".go")],
            debug = False,
            imports = imports,
            package = name,
        )
        extra_deps = [
            dep
            for dep in marshal_deps
            if not dep in all_deps
        ]
        all_deps = all_deps + extra_deps
        all_srcs = srcs + [name + "_abi_autogen_unsafe.go"]

    _go_library(
        name = name,
        srcs = all_srcs,
        deps = all_deps,
        **kwargs
    )

    if marshal:
        # Ignore importpath for go_test.
        kwargs.pop("importpath", None)

        _go_test(
            name = name + "_abi_autogen_test",
            srcs = [name + "_abi_autogen_test.go"],
            library = ":" + name,
            deps = marshal_test_deps,
            **kwargs
        )

def proto_library(name, srcs, **kwargs):
    """Wraps the standard proto_library.

    Given a proto_library named "foo", this produces three different targets:
    - foo_proto: proto_library rule.
    - foo_go_proto: go_proto_library rule.
    - foo_cc_proto: cc_proto_library rule.

    Args:
      srcs: the proto sources.
      **kwargs: standard proto_library arguments.
    """
    deps = kwargs.pop("deps", [])
    _proto_library(
        name = name + "_proto",
        srcs = srcs,
        deps = deps,
        **kwargs
    )
    _go_proto_library(
        name = name + "_go_proto",
        proto = ":" + name + "_proto",
        deps = deps,
        **kwargs
    )
    _cc_proto_library(
        name = name + "_cc_proto",
        deps = [":" + name + "_proto"],
        **kwargs
    )

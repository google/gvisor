"""Bazel implementations of standard rules."""

load("@bazel_tools//tools/cpp:cc_flags_supplier.bzl", _cc_flags_supplier = "cc_flags_supplier")
load("@io_bazel_rules_go//go:def.bzl", _go_binary = "go_binary", _go_embed_data = "go_embed_data", _go_library = "go_library", _go_test = "go_test", _go_tool_library = "go_tool_library")
load("@io_bazel_rules_go//proto:def.bzl", _go_proto_library = "go_proto_library")
load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library", _cc_proto_library = "cc_proto_library", _cc_test = "cc_test")
load("@rules_pkg//:pkg.bzl", _pkg_deb = "pkg_deb", _pkg_tar = "pkg_tar")
load("@io_bazel_rules_docker//go:image.bzl", _go_image = "go_image")
load("@io_bazel_rules_docker//container:container.bzl", _container_image = "container_image")
load("@pydeps//:requirements.bzl", _py_requirement = "requirement")

container_image = _container_image
cc_binary = _cc_binary
cc_library = _cc_library
cc_flags_supplier = _cc_flags_supplier
cc_proto_library = _cc_proto_library
cc_test = _cc_test
cc_toolchain = "@bazel_tools//tools/cpp:current_cc_toolchain"
go_image = _go_image
go_embed_data = _go_embed_data
gtest = "@com_google_googletest//:gtest"
loopback = "//tools/build:loopback"
proto_library = native.proto_library
pkg_deb = _pkg_deb
pkg_tar = _pkg_tar
py_library = native.py_library
py_binary = native.py_binary
py_test = native.py_test

def go_binary(name, static = False, pure = False, **kwargs):
    if static:
        kwargs["static"] = "on"
    if pure:
        kwargs["pure"] = "on"
    _go_binary(
        name = name,
        **kwargs
    )

def go_library(name, **kwargs):
    _go_library(
        name = name,
        importpath = "gvisor.dev/gvisor/" + native.package_name(),
        **kwargs
    )

def go_tool_library(name, **kwargs):
    _go_tool_library(
        name = name,
        importpath = "gvisor.dev/gvisor/" + native.package_name(),
        **kwargs
    )

def go_proto_library(name, proto, **kwargs):
    deps = kwargs.pop("deps", [])
    _go_proto_library(
        name = name,
        importpath = "gvisor.dev/gvisor/" + native.package_name() + "/" + name,
        proto = proto,
        deps = [dep.replace("_proto", "_go_proto") for dep in deps],
        **kwargs
    )

def go_test(name, **kwargs):
    library = kwargs.pop("library", None)
    if library:
        kwargs["embed"] = [library]
    _go_test(
        name = name,
        **kwargs
    )

def py_requirement(name, direct = False):
    return _py_requirement(name)

def select_arch(amd64 = "amd64", arm64 = "arm64", default = None, **kwargs):
    values = {
        "@bazel_tools//src/conditions:linux_x86_64": amd64,
        "@bazel_tools//src/conditions:linux_aarch64": arm64,
    }
    if default:
        values["//conditions:default"] = default
    return select(values, **kwargs)

def select_system(linux = ["__linux__"], **kwargs):
    return linux  # Only Linux supported.

def default_installer():
    return None

def default_net_util():
    return []  # Nothing needed.

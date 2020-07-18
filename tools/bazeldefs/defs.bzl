"""Bazel implementations of standard rules."""

load("@bazel_gazelle//:def.bzl", _gazelle = "gazelle")
load("@bazel_skylib//rules:build_test.bzl", _build_test = "build_test")
load("@bazel_tools//tools/cpp:cc_flags_supplier.bzl", _cc_flags_supplier = "cc_flags_supplier")
load("@io_bazel_rules_go//go:def.bzl", "GoLibrary", _go_binary = "go_binary", _go_context = "go_context", _go_embed_data = "go_embed_data", _go_library = "go_library", _go_path = "go_path", _go_test = "go_test")
load("@io_bazel_rules_go//proto:def.bzl", _go_grpc_library = "go_grpc_library", _go_proto_library = "go_proto_library")
load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library", _cc_proto_library = "cc_proto_library", _cc_test = "cc_test")
load("@rules_pkg//:pkg.bzl", _pkg_deb = "pkg_deb", _pkg_tar = "pkg_tar")
load("@pydeps//:requirements.bzl", _py_requirement = "requirement")
load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", _cc_grpc_library = "cc_grpc_library")

build_test = _build_test
cc_library = _cc_library
cc_flags_supplier = _cc_flags_supplier
cc_proto_library = _cc_proto_library
cc_test = _cc_test
cc_toolchain = "@bazel_tools//tools/cpp:current_cc_toolchain"
gazelle = _gazelle
go_embed_data = _go_embed_data
go_path = _go_path
gtest = "@com_google_googletest//:gtest"
grpcpp = "@com_github_grpc_grpc//:grpc++"
gbenchmark = "@com_google_benchmark//:benchmark"
loopback = "//tools/bazeldefs:loopback"
pkg_deb = _pkg_deb
pkg_tar = _pkg_tar
py_library = native.py_library
py_binary = native.py_binary
py_test = native.py_test
rbe_platform = native.platform
rbe_toolchain = native.toolchain
vdso_linker_option = "-fuse-ld=gold "

def short_path(path):
    return path

def proto_library(name, has_services = None, **kwargs):
    native.proto_library(
        name = name,
        **kwargs
    )

def cc_grpc_library(name, **kwargs):
    _cc_grpc_library(name = name, grpc_only = True, **kwargs)

def _go_proto_or_grpc_library(go_library_func, name, **kwargs):
    deps = [
        dep.replace("_proto", "_go_proto")
        for dep in (kwargs.pop("deps", []) or [])
    ]
    go_library_func(
        name = name + "_go_proto",
        importpath = "gvisor.dev/gvisor/" + native.package_name() + "/" + name + "_go_proto",
        proto = ":" + name + "_proto",
        deps = deps,
        **kwargs
    )

def go_proto_library(name, **kwargs):
    _go_proto_or_grpc_library(_go_proto_library, name, **kwargs)

def go_grpc_and_proto_libraries(name, **kwargs):
    _go_proto_or_grpc_library(_go_grpc_library, name, **kwargs)

def cc_binary(name, static = False, **kwargs):
    """Run cc_binary.

    Args:
        name: name of the target.
        static: make a static binary if True
        **kwargs: the rest of the args.
    """
    if static:
        # How to statically link a c++ program that uses threads, like for gRPC:
        # https://gcc.gnu.org/legacy-ml/gcc-help/2010-05/msg00029.html
        if "linkopts" not in kwargs:
            kwargs["linkopts"] = []
        kwargs["linkopts"] += [
            "-static",
            "-lstdc++",
            "-Wl,--whole-archive",
            "-lpthread",
            "-Wl,--no-whole-archive",
        ]
    _cc_binary(
        name = name,
        **kwargs
    )

def go_binary(name, static = False, pure = False, **kwargs):
    """Build a go binary.

    Args:
        name: name of the target.
        static: build a static binary.
        pure: build without cgo.
        **kwargs: rest of the arguments are passed to _go_binary.
    """
    if static:
        kwargs["static"] = "on"
    if pure:
        kwargs["pure"] = "on"
    _go_binary(
        name = name,
        **kwargs
    )

def go_importpath(target):
    """Returns the importpath for the target."""
    return target[GoLibrary].importpath

def go_library(name, **kwargs):
    _go_library(
        name = name,
        importpath = "gvisor.dev/gvisor/" + native.package_name(),
        **kwargs
    )

def go_test(name, pure = False, library = None, **kwargs):
    """Build a go test.

    Args:
        name: name of the output binary.
        pure: should it be built without cgo.
        library: the library to embed.
        **kwargs: rest of the arguments to pass to _go_test.
    """
    if pure:
        kwargs["pure"] = "on"
    if library:
        kwargs["embed"] = [library]
    _go_test(
        name = name,
        **kwargs
    )

def go_rule(rule, implementation, **kwargs):
    """Wraps a rule definition with Go attributes.

    Args:
      rule: rule function (typically rule or aspect).
      implementation: implementation function.
      **kwargs: other arguments to pass to rule.

    Returns:
        The result of invoking the rule.
    """
    attrs = kwargs.pop("attrs", [])
    attrs["_go_context_data"] = attr.label(default = "@io_bazel_rules_go//:go_context_data")
    attrs["_stdlib"] = attr.label(default = "@io_bazel_rules_go//:stdlib")
    toolchains = kwargs.get("toolchains", []) + ["@io_bazel_rules_go//go:toolchain"]
    return rule(implementation, attrs = attrs, toolchains = toolchains, **kwargs)

def go_context(ctx):
    go_ctx = _go_context(ctx)
    return struct(
        go = go_ctx.go,
        env = go_ctx.env,
        runfiles = depset([go_ctx.go] + go_ctx.sdk.tools + go_ctx.stdlib.libs),
        goos = go_ctx.sdk.goos,
        goarch = go_ctx.sdk.goarch,
        tags = go_ctx.tags,
    )

def py_requirement(name, direct = True):
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

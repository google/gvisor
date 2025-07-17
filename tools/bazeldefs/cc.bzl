"""C++ rules."""

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", _cc_grpc_library = "cc_grpc_library")
load("@com_google_protobuf//bazel:cc_proto_library.bzl", _cc_proto_library = "cc_proto_library")
load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library", _cc_test = "cc_test")

cc_library = _cc_library
cc_proto_library = _cc_proto_library
cc_test = _cc_test
cc_toolchain = "@bazel_tools//tools/cpp:current_cc_toolchain"
gtest = "@com_google_googletest//:gtest"
gbenchmark = "@com_google_benchmark//:benchmark"
gbenchmark_internal = "@com_google_benchmark//:benchmark"
grpcpp = "@com_github_grpc_grpc//:grpc++"

def _cc_flags_supplier_impl(ctx):
    variables = platform_common.TemplateVariableInfo({
        "CC_FLAGS": "",
    })
    return [variables]

cc_flags_supplier = rule(
    implementation = _cc_flags_supplier_impl,
)

def cc_grpc_library(name, **kwargs):
    _cc_grpc_library(name = name, grpc_only = True, **kwargs)

def cc_binary(name, static = False, tcmalloc = False, **kwargs):
    """Run cc_binary.

    Args:
        name: name of the target.
        static: make a static binary if True
        tcmalloc: use TCMalloc if True (not implemented)
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
    if tcmalloc:
        # buildifier: disable=print
        print("Warning: tcmalloc can't be enabled")

    _cc_binary(
        name = name,
        **kwargs
    )

def select_gtest():
    return [gtest]  # No select is needed.

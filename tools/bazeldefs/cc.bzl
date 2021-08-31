"""C++ rules."""

load("@rules_cc//cc:defs.bzl", _cc_binary = "cc_binary", _cc_library = "cc_library", _cc_proto_library = "cc_proto_library", _cc_test = "cc_test")
load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", _cc_grpc_library = "cc_grpc_library")

cc_library = _cc_library
cc_proto_library = _cc_proto_library
cc_test = _cc_test
cc_toolchain = "@bazel_tools//tools/cpp:current_cc_toolchain"
gtest = "@com_google_googletest//:gtest"
gbenchmark = "@com_google_benchmark//:benchmark"
gbenchmark_internal = "@com_google_benchmark//:benchmark"
grpcpp = "@com_github_grpc_grpc//:grpc++"
vdso_linker_option = "-fuse-ld=gold "

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

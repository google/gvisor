# Package fsbench provides utility functions for filesystem-related benchmarks.

load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//test/benchmarks/fs:__subpackages__"],
    licenses = ["notice"],
)

go_library(
    name = "fsbench",
    testonly = 1,
    srcs = ["fsbench.go"],
    deps = [
        "//pkg/cleanup",
        "//pkg/test/dockerutil",
        "//test/benchmarks/harness",
        "//test/benchmarks/tools",
    ],
)

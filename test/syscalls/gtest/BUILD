load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "gtest",
    srcs = ["gtest.go"],
    importpath = "gvisor.googlesource.com/gvisor/test/syscalls/gtest",
    visibility = [
        "//test:__subpackages__",
    ],
)

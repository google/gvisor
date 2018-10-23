load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "globals",
    srcs = [
        "globals_visitor.go",
        "scope.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/tools/go_generics/globals",
    visibility = ["//tools/go_generics:__pkg__"],
)

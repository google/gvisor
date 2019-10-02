load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_marshal:defs.bzl", "go_library")

package_group(
    name = "gomarshal_test",
    packages = [
        "//tools/go_marshal/test/...",
    ],
)

go_test(
    name = "benchmark_test",
    srcs = ["benchmark_test.go"],
    deps = [
        ":test",
        "//pkg/binary",
        "//pkg/sentry/usermem",
        "//tools/go_marshal/analysis",
    ],
)

go_library(
    name = "test",
    testonly = 1,
    srcs = ["test.go"],
    importpath = "gvisor.dev/gvisor/tools/go_marshal/test",
    deps = ["//tools/go_marshal/test/external"],
)

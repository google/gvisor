load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "secio",
    srcs = [
        "full_reader.go",
        "secio.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/secio",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "secio_test",
    size = "small",
    srcs = ["secio_test.go"],
    embed = [":secio"],
)

load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "interrupt",
    srcs = [
        "interrupt.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/platform/interrupt",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "interrupt_test",
    size = "small",
    srcs = ["interrupt_test.go"],
    embed = [":interrupt"],
)

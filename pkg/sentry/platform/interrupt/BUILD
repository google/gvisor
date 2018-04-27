package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "interrupt",
    srcs = [
        "interrupt.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/platform/interrupt",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "interrupt_test",
    size = "small",
    srcs = ["interrupt_test.go"],
    embed = [":interrupt"],
)

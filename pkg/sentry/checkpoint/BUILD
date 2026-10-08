load("//tools:defs.bzl", "go_library", "go_test")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "checkpoint",
    srcs = ["checkpoint.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/checkpoint",
    visibility = ["//pkg/sentry:internal"],
)

go_test(
    name = "checkpoint_test",
    size = "small",
    srcs = ["checkpoint_test.go"],
    embed = [":checkpoint"],
)

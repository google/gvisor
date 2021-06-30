load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "experiment",
    srcs = ["foo.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/sentry/kernel/time",
    ],
)

go_test(
    name = "experiment_test",
    size = "small",
    srcs = ["foo_test.go"],
    embed = [":experiment"],
    deps = [
        "//pkg/sentry/kernel/time",
    ],
)

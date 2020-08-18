load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "contexttest",
    testonly = 1,
    srcs = ["contexttest.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/kernel",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
    ],
)

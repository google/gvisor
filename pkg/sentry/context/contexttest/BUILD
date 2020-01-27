load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "contexttest",
    testonly = 1,
    srcs = ["contexttest.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/memutil",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/ptrace",
        "//pkg/sentry/uniqueid",
    ],
)

package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "contexttest",
    testonly = 1,
    srcs = ["contexttest.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/context/contexttest",
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

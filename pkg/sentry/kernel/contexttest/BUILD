package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "contexttest",
    testonly = 1,
    srcs = ["contexttest.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/contexttest",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
    ],
)

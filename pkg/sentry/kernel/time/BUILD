package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "time",
    srcs = [
        "context.go",
        "time.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

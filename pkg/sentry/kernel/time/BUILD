package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "time",
    srcs = [
        "context.go",
        "kicker_timer.go",
        "time.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/time",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

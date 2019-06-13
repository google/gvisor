package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "fasync",
    srcs = ["fasync.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/fasync",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/waiter",
    ],
)

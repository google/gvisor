package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "shm",
    srcs = [
        "device.go",
        "shm.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/kernel/shm",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)

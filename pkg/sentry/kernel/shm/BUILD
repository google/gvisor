load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "shm",
    srcs = [
        "device.go",
        "shm.go",
    ],
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
        "//pkg/sync",
        "//pkg/syserror",
    ],
)

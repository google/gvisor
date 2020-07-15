load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "memdev",
    srcs = [
        "full.go",
        "kmsg.go",
        "memdev.go",
        "null.go",
        "random.go",
        "zero.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/rand",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/mm",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

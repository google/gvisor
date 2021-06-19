load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "iouringfs",
    srcs = ["iouringfs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/safemem",
        "//pkg/hostarch",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/syserror",

    ],
)

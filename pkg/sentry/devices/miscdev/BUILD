load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "miscdev",
    srcs = [
        "fuse.go",
        "miscdev.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "fuse",
    srcs = [
        "dev.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

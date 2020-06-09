load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "fuse",
    srcs = [
        "dev.go",
        "fusefs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

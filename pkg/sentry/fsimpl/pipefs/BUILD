load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "pipefs",
    srcs = ["pipefs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

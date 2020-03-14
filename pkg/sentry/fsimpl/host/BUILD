load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "host",
    srcs = [
        "default_file.go",
        "host.go",
        "util.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

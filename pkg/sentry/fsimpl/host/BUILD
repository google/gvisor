load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "host",
    srcs = [
        "control.go",
        "host.go",
        "ioctl_unsafe.go",
        "tty.go",
        "util.go",
        "util_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "host",
    srcs = [
        "host.go",
        "host_unsafe.go",
        "ioctl_unsafe.go",
        "save_restore.go",
        "tty.go",
        "util.go",
        "util_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/eventfd",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/unet",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

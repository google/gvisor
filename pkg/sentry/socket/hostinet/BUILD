package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "hostinet",
    srcs = [
        "device.go",
        "hostinet.go",
        "save_restore.go",
        "socket.go",
        "socket_unsafe.go",
        "stack.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
        "//pkg/waiter/fdnotifier",
    ],
)

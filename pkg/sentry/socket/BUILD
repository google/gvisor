package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "socket",
    srcs = ["socket.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/tcpip",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "socket",
    srcs = ["socket.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/tcpip",
    ],
)

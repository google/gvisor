package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "netlink_state",
    srcs = [
        "socket.go",
    ],
    out = "netlink_state.go",
    package = "netlink",
)

go_library(
    name = "netlink",
    srcs = [
        "message.go",
        "netlink_state.go",
        "provider.go",
        "socket.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/kdefs",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/netlink/port",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
    ],
)

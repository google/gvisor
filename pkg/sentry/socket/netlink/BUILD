load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "netlink",
    srcs = [
        "message.go",
        "provider.go",
        "provider_vfs2.go",
        "socket.go",
        "socket_vfs2.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/bits",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/netlink/port",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "netlink_test",
    size = "small",
    srcs = [
        "message_test.go",
    ],
    deps = [
        ":netlink",
        "//pkg/abi/linux",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
    ],
)

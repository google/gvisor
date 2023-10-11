package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "externalstack",
    srcs = [
        "notifier.go",
        "provider.go",
        "socket.go",
        "stack.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sentry/inet",
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/sentry/arch",
        "//pkg/sentry/stack",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/externalstack/cgo",
        "//pkg/sentry/vfs",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/usermem",
        "//pkg/waiter",
        "//pkg/sentry/kernel/auth",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
    ],
)

load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stack",
    srcs = [
        "notifier.go",
        "provider.go",
        "readwriter.go",
        "socket.go",
        "stack.go",
        "util.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
        "//pkg/atomicbitops",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/sockfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/ktime",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/plugin",
        "//pkg/sentry/socket/plugin/cgo",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/vfs",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "stack_test",
    size = "small",
    srcs = ["socket_test.go"],
    library = ":stack",
    deps = ["//pkg/waiter"],
)

load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "socket",
    srcs = ["socket.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/marshal",
        "//pkg/sentry/kernel",
        "//pkg/sentry/ktime",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/usermem",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "socket_test",
    size = "small",
    srcs = ["socket_test.go"],
    embed = [":socket"],
    deps = [
        "//pkg/abi/linux",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

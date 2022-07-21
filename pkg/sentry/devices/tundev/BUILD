load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "tundev",
    srcs = ["tundev.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/bufferv2",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket/netstack",
        "//pkg/sentry/vfs",
        "//pkg/tcpip/link/tun",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

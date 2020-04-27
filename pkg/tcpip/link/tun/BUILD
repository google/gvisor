load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "tun",
    srcs = [
        "device.go",
        "protocol.go",
        "tun_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

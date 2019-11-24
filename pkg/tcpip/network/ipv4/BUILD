load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ipv4",
    srcs = [
        "icmp.go",
        "ipv4.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/network/ipv4",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/fragmentation",
        "//pkg/tcpip/network/hash",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ipv4_test",
    size = "small",
    srcs = ["ipv4_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "ipv6",
    srcs = [
        "icmp.go",
        "ipv6.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ipv6_test",
    size = "small",
    srcs = ["icmp_test.go"],
    embed = [":ipv6"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/ping",
        "//pkg/waiter",
    ],
)

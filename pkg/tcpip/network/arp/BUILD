load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "arp",
    srcs = ["arp.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/arp",
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
    name = "arp_test",
    size = "small",
    srcs = ["arp_test.go"],
    deps = [
        ":arp",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/ping",
    ],
)

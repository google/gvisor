load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "utils",
    srcs = ["utils.go"],
    visibility = ["//pkg/tcpip/tests:__subpackages__"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/link/pipe",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/udp",
    ],
)

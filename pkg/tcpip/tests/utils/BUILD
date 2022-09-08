load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "utils",
    testonly = True,
    srcs = ["utils.go"],
    visibility = ["//pkg/tcpip/tests:__subpackages__"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/link/pipe",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/prependable",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/icmp",
    ],
)

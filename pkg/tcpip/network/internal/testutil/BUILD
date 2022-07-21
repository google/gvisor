load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "testutil",
    srcs = ["testutil.go"],
    visibility = [
        "//pkg/tcpip/network/arp:__pkg__",
        "//pkg/tcpip/network/internal/fragmentation:__pkg__",
        "//pkg/tcpip/network/ipv4:__pkg__",
        "//pkg/tcpip/network/ipv6:__pkg__",
        "//pkg/tcpip/tests/integration:__pkg__",
    ],
    deps = [
        "//pkg/bufferv2",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

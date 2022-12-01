load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "network",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
    ],
    visibility = [
        "//pkg/tcpip/transport/icmp:__pkg__",
        "//pkg/tcpip/transport/raw:__pkg__",
        "//pkg/tcpip/transport/udp:__pkg__",
    ],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
        "//pkg/waiter",
    ],
)

go_test(
    name = "network_test",
    size = "small",
    srcs = ["endpoint_test.go"],
    deps = [
        ":network",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

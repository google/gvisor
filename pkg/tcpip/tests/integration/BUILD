load("//tools:defs.bzl", "go_test")

package(licenses = ["notice"])

go_test(
    name = "integration_test",
    size = "small",
    srcs = [
        "forward_test.go",
        "link_resolution_test.go",
        "loopback_test.go",
        "multicast_broadcast_test.go",
        "route_test.go",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/link/pipe",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

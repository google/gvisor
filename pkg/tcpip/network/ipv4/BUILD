load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ipv4",
    srcs = [
        "icmp.go",
        "igmp.go",
        "ipv4.go",
        "stats.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/network/fragmentation",
        "//pkg/tcpip/network/hash",
        "//pkg/tcpip/network/ip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ipv4_test",
    size = "small",
    srcs = [
        "igmp_test.go",
        "ipv4_test.go",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/testutil",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "stats_test",
    size = "small",
    srcs = ["stats_test.go"],
    library = ":ipv4",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/network/testutil",
        "//pkg/tcpip/stack",
    ],
)

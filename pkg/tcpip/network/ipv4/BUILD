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
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/network/hash",
        "//pkg/tcpip/network/internal/fragmentation",
        "//pkg/tcpip/network/internal/ip",
        "//pkg/tcpip/network/internal/multicast",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ipv4_test",
    size = "small",
    srcs = [
        "igmp_test.go",
        "ipv4_test.go",
        "main_test.go",
    ],
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/internal/testutil",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/prependable",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/raw",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

go_test(
    name = "stats_test",
    size = "small",
    srcs = ["stats_test.go"],
    library = ":ipv4",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
    ],
)

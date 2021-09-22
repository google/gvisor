load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ipv6",
    srcs = [
        "dhcpv6configurationfromndpra_string.go",
        "icmp.go",
        "ipv6.go",
        "mld.go",
        "ndp.go",
        "stats.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/network/hash",
        "//pkg/tcpip/network/internal/fragmentation",
        "//pkg/tcpip/network/internal/ip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ipv6_test",
    size = "small",
    srcs = [
        "icmp_test.go",
        "ipv6_test.go",
        "ndp_test.go",
    ],
    library = ":ipv6",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/internal/testutil",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "ipv6_x_test",
    size = "small",
    srcs = ["mld_test.go"],
    deps = [
        ":ipv6",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
    ],
)

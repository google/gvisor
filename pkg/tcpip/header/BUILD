load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "header",
    srcs = [
        "arp.go",
        "checksum.go",
        "eth.go",
        "gue.go",
        "icmpv4.go",
        "icmpv6.go",
        "igmp.go",
        "interfaces.go",
        "ipv4.go",
        "ipv6.go",
        "ipv6_extension_headers.go",
        "ipv6_fragment.go",
        "mld.go",
        "ndp_neighbor_advert.go",
        "ndp_neighbor_solicit.go",
        "ndp_options.go",
        "ndp_router_advert.go",
        "ndp_router_solicit.go",
        "ndpoptionidentifier_string.go",
        "tcp.go",
        "udp.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/seqnum",
        "@com_github_google_btree//:go_default_library",
    ],
)

go_test(
    name = "header_x_test",
    size = "small",
    srcs = [
        "checksum_test.go",
        "igmp_test.go",
        "ipv4_test.go",
        "ipv6_test.go",
        "ipversion_test.go",
        "tcp_test.go",
    ],
    deps = [
        ":header",
        "//pkg/rand",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "header_test",
    size = "small",
    srcs = [
        "eth_test.go",
        "ipv6_extension_headers_test.go",
        "mld_test.go",
        "ndp_test.go",
    ],
    library = ":header",
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

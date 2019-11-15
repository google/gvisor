load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

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
        "interfaces.go",
        "ipv4.go",
        "ipv6.go",
        "ipv6_fragment.go",
        "ndp_neighbor_advert.go",
        "ndp_neighbor_solicit.go",
        "ndp_options.go",
        "ndp_router_advert.go",
        "tcp.go",
        "udp.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/header",
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
        "ipversion_test.go",
        "tcp_test.go",
    ],
    deps = [
        ":header",
        "//pkg/tcpip/buffer",
    ],
)

go_test(
    name = "header_test",
    size = "small",
    srcs = [
        "eth_test.go",
        "ndp_test.go",
    ],
    embed = [":header"],
    deps = [
        "//pkg/tcpip",
        "@com_github_google_go-cmp//cmp:go_default_library",
    ],
)

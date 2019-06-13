package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

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
    name = "header_test",
    size = "small",
    srcs = [
        "ipversion_test.go",
        "tcp_test.go",
    ],
    deps = [
        ":header",
    ],
)

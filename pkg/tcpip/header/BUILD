package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "tcp_header_state",
    srcs = [
        "tcp.go",
    ],
    out = "tcp_header_state.go",
    package = "header",
)

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
        "tcp_header_state.go",
        "udp.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/header",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/seqnum",
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

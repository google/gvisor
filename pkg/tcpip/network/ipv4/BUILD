package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "ipv4",
    srcs = [
        "icmp.go",
        "ipv4.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/fragmentation",
        "//pkg/tcpip/network/hash",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

go_test(
    name = "ipv4_test",
    size = "small",
    srcs = ["icmp_test.go"],
    deps = [
        ":ipv4",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/stack",
    ],
)

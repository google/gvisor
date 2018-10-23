load("@io_bazel_rules_go//go:def.bzl", "go_binary")

package(licenses = ["notice"])  # Apache 2.0

go_binary(
    name = "tun_tcp_connect",
    srcs = ["main.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/link/tun",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
    ],
)

package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "dhcp",
    srcs = [
        "client.go",
        "dhcp.go",
        "server.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/dhcp",
    deps = [
        "//pkg/rand",
        "//pkg/tcpip",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
    ],
)

go_test(
    name = "dhcp_test",
    size = "small",
    srcs = ["dhcp_test.go"],
    embed = [":dhcp"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/udp",
    ],
)

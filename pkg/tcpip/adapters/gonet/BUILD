package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "gonet",
    srcs = ["gonet.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/adapters/gonet",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
    ],
)

go_test(
    name = "gonet_test",
    size = "small",
    srcs = ["gonet_test.go"],
    embed = [":gonet"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@org_golang_x_net//nettest:go_default_library",
    ],
)

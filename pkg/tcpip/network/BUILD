package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_test")

go_test(
    name = "ip_test",
    size = "small",
    srcs = [
        "ip_test.go",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
    ],
)

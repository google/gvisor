package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "ipv6",
    srcs = [
        "icmp.go",
        "ipv6.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

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
    ],
)

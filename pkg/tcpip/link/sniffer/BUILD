package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "sniffer",
    srcs = [
        "pcap.go",
        "sniffer.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/sniffer",
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

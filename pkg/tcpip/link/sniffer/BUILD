package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library")

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
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/stack",
    ],
)

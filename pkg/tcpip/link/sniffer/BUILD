load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sniffer",
    srcs = ["sniffer.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/sniffer/pcap",
        "//pkg/tcpip/stack",
    ],
)

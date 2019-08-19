load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sniffer",
    srcs = [
        "pcap.go",
        "sniffer.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/link/sniffer",
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

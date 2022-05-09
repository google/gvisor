load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "sniffer",
    srcs = [
        "pcap.go",
        "sniffer.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
    ],
)

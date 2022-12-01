load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "context",
    testonly = 1,
    srcs = [
        "context.go",
        "flow.go",
    ],
    visibility = [
        "//visibility:public",
    ],
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

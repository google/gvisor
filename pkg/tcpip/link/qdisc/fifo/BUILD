load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fifo",
    srcs = [
        "endpoint.go",
        "packet_buffer_queue.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "qdisc_test",
    size = "small",
    srcs = ["qdisc_test.go"],
    deps = [
        ":fifo",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
    ],
)

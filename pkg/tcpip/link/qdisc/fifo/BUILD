load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fifo",
    srcs = [
        "fifo.go",
        "packet_buffer_circular_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "qdisc_test",
    size = "small",
    srcs = ["qdisc_test.go"],
    deps = [
        ":fifo",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

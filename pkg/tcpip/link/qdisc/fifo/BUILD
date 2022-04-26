load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fifo",
    srcs = [
        "fifo.go",
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
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)

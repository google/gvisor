load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "dispatcher_mutex",
    out = "dispatcher_mutex.go",
    package = "fifo",
    prefix = "queueDispatcher",
)

go_library(
    name = "fifo",
    srcs = [
        "dispatcher_mutex.go",
        "fifo.go",
        "packet_buffer_circular_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/sync/locking",
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
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

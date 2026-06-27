load("//pkg/sync/locking:locking.bzl", "declare_mutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "queue_mutex",
    out = "queue_mutex.go",
    package = "tbf",
    prefix = "queue",
)

declare_mutex(
    name = "ingress_queue_mutex",
    out = "ingress_queue_mutex.go",
    package = "tbf",
    prefix = "ingressQueue",
)

go_library(
    name = "tbf",
    srcs = [
        "ingress.go",
        "ingress_queue_mutex.go",
        "queue_mutex.go",
        "tbf.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/link/qdisc",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "tbf_test",
    size = "small",
    srcs = [
        "ingress_test.go",
        "tbf_test.go",
    ],
    deps = [
        ":tbf",
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

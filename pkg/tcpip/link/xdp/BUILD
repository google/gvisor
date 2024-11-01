load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "xdp",
    prefix = "endpoint",
)

go_library(
    name = "xdp",
    srcs = [
        "endpoint.go",
        "endpoint_mutex.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/buffer",
        "//pkg/rawfile",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/qdisc/fifo",
        "//pkg/tcpip/link/stopfd",
        "//pkg/tcpip/stack",
        "//pkg/xdp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "xdp_test",
    srcs = ["endpoint_test.go"],
    library = ":xdp",
    deps = ["//pkg/tcpip"],
)

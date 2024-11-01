load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "muxed",
    prefix = "endpoint",
)

go_library(
    name = "muxed",
    srcs = [
        "endpoint_mutex.go",
        "injectable.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/buffer",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "muxed_test",
    size = "small",
    srcs = ["injectable_test.go"],
    library = ":muxed",
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/link/fdbased",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

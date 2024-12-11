load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "veth_mutex",
    out = "veth_mutex.go",
    package = "veth",
    prefix = "veth",
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "veth",
    prefix = "endpoint",
)

go_library(
    name = "veth",
    srcs = [
        "endpoint_mutex.go",
        "veth.go",
        "veth_mutex.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "veth_test",
    size = "small",
    srcs = [
        "veth_test.go",
    ],
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/ethernet",
        "//pkg/tcpip/link/veth",
        "//pkg/tcpip/stack",
    ],
)

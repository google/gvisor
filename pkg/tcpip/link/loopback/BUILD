load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "loopback",
    prefix = "endpoint",
)

go_library(
    name = "loopback",
    srcs = [
        "endpoint_mutex.go",
        "loopback.go",
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

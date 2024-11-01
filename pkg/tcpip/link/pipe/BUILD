load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "pipe",
    prefix = "endpoint",
)

go_library(
    name = "pipe",
    srcs = [
        "endpoint_mutex.go",
        "pipe.go",
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
    name = "pipe_test",
    srcs = ["pipe_test.go"],
    library = ":pipe",
    deps = ["//pkg/tcpip"],
)

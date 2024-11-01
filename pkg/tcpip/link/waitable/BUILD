load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "waitable",
    prefix = "endpoint",
)

go_library(
    name = "waitable",
    srcs = [
        "endpoint_mutex.go",
        "waitable.go",
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
    name = "waitable_test",
    srcs = [
        "waitable_test.go",
    ],
    library = ":waitable",
    deps = [
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

load("//pkg/sync/locking:locking.bzl", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_rwmutex(
    name = "endpoint_mutex",
    out = "endpoint_mutex.go",
    package = "channel",
    prefix = "endpoint",
)

declare_rwmutex(
    name = "queue_mutex",
    out = "queue_mutex.go",
    package = "channel",
    prefix = "queue",
)

go_library(
    name = "channel",
    srcs = [
        "channel.go",
        "endpoint_mutex.go",
        "queue_mutex.go",
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
    name = "channel_test",
    srcs = ["channel_test.go"],
    library = ":channel",
    deps = ["//pkg/tcpip"],
)

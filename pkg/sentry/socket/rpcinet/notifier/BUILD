load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "notifier",
    srcs = ["notifier.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket/rpcinet/notifier",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/sentry/socket/rpcinet:syscall_rpc_go_proto",
        "//pkg/sentry/socket/rpcinet/conn",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

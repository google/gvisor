package(licenses = ["notice"])  # BSD

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "notifier",
    srcs = ["notifier.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/notifier",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/sentry/socket/rpcinet:syscall_rpc_go_proto",
        "//pkg/sentry/socket/rpcinet/conn",
        "//pkg/waiter",
    ],
)

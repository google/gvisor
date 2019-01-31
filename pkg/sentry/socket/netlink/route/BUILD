package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "route",
    srcs = ["protocol.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/socket/netlink/route",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/netlink",
        "//pkg/syserr",
    ],
)

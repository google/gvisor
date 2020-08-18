load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "route",
    srcs = [
        "protocol.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/netlink",
        "//pkg/syserr",
    ],
)

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
        "//pkg/marshal/primitive",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/netlink",
        "//pkg/syserr",
        "//pkg/syserror",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

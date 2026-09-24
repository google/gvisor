load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "rdma",
    srcs = ["protocol.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/ib",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/marshal/primitive",
        "//pkg/rdma",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket/netlink",
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/syserr",
    ],
)

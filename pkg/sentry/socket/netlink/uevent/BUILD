load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "uevent",
    srcs = ["protocol.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket/netlink",
        "//pkg/syserr",
    ],
)

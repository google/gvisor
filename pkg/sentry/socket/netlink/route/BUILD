load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "route",
    srcs = [
        "protocol.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/marshal/primitive",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket/netlink",
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/syserr",
    ],
)

go_test(
    name = "route_test",
    size = "small",
    srcs = [
        "protocol_test.go",
    ],
    library = ":route",
    deps = [
        "//pkg/abi/linux",
        "//pkg/marshal/primitive",
        "//pkg/sentry/inet",
        "//pkg/sentry/socket/netlink/nlmsg",
        "//pkg/syserr",
    ],
)

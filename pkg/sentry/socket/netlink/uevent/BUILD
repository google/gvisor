load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "uevent",
    srcs = ["protocol.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket/netlink/uevent",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel",
        "//pkg/sentry/socket/netlink",
        "//pkg/syserr",
    ],
)

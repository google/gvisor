load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "fasync",
    srcs = ["fasync.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)

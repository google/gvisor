load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "signalfd",
    srcs = ["signalfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/context",
        "//pkg/sentry/kernel",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

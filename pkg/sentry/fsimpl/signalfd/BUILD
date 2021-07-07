load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "signalfd",
    srcs = ["signalfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

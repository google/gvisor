load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "quotedev",
    srcs = ["quotedev.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/vfs",
    ],
)

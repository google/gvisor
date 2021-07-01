load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "sockfs",
    srcs = ["sockfs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)

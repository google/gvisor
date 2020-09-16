load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "verity",
    srcs = [
        "filesystem.go",
        "verity.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/marshal/primitive",
        "//pkg/merkletree",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

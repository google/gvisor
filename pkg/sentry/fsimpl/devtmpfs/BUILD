load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "devtmpfs",
    srcs = [
        "devtmpfs.go",
        "save_restore.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)

go_test(
    name = "devtmpfs_test",
    size = "small",
    srcs = ["devtmpfs_test.go"],
    library = ":devtmpfs",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)

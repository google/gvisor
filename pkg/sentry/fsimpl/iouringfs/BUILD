load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "iouringfs",
    srcs = ["iouringfs.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
    ],
)

go_test(
    name = "iouringfs_test",
    size = "small",
    srcs = ["iouringfs_test.go"],
    library = ":iouringfs",
)

load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "iouringfs",
    srcs = [
        "buffer.go",
        "iouringfs.go",
        "iouringfs_state.go",
        "iouringfs_unsafe.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/safemem",
        "//pkg/sentry/kernel",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
    ],
)

go_test(
    name = "iouringfs_test",
    size = "small",
    srcs = ["iouringfs_test.go"],
    library = ":iouringfs",
    deps = ["//pkg/hostarch"],
)

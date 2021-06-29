load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "pipe",
    srcs = [
        "device.go",
        "node.go",
        "pipe.go",
        "pipe_unsafe.go",
        "pipe_util.go",
        "reader.go",
        "reader_writer.go",
        "save_restore.go",
        "vfs.go",
        "writer.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/marshal/primitive",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "pipe_test",
    size = "small",
    srcs = [
        "node_test.go",
        "pipe_test.go",
    ],
    library = ":pipe",
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

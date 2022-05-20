load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "vfs_mutex",
    out = "vfs_mutex.go",
    package = "pipe",
    prefix = "vfs",
    substrs = {
        "genericMark": "vfs",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "pipe_mutex",
    out = "pipe_mutex.go",
    package = "pipe",
    prefix = "pipe",
    substrs = {
        "genericMark": "pipe",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "inode_mutex",
    out = "inode_mutex.go",
    package = "pipe",
    prefix = "inode",
    substrs = {
        "genericMark": "inode",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_library(
    name = "pipe",
    srcs = [
        "device.go",
        "inode_mutex.go",
        "node.go",
        "pipe.go",
        "pipe_mutex.go",
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
        "//pkg/atomicbitops",
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
        "//pkg/sync/locking",
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
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

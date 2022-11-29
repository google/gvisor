load("//tools:defs.bzl", "go_library", "go_test")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(licenses = ["notice"])

declare_mutex(
    name = "vfs_mutex",
    out = "vfs_mutex.go",
    package = "pipe",
    prefix = "vfs",
)

declare_mutex(
    name = "pipe_mutex",
    out = "pipe_mutex.go",
    nested_lock_names = ["pipe"],
    package = "pipe",
    prefix = "pipe",
)

declare_mutex(
    name = "inode_mutex",
    out = "inode_mutex.go",
    package = "pipe",
    prefix = "inode",
)

go_library(
    name = "pipe",
    srcs = [
        "device.go",
        "inode_mutex.go",
        "pipe.go",
        "pipe_mutex.go",
        "pipe_unsafe.go",
        "pipe_util.go",
        "save_restore.go",
        "vfs.go",
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
        "//pkg/sentry/fsutil",
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
        "pipe_test.go",
    ],
    library = ":pipe",
    deps = [
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

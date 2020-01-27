load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tmpfs",
    srcs = [
        "device.go",
        "file_regular.go",
        "fs.go",
        "inode_file.go",
        "tmpfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/metric",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tmpfs_test",
    size = "small",
    srcs = ["file_test.go"],
    library = ":tmpfs",
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
    ],
)

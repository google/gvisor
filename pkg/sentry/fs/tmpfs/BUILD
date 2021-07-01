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
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/safemem",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tmpfs_test",
    size = "small",
    srcs = ["file_test.go"],
    library = ":tmpfs",
    deps = [
        "//pkg/context",
        "//pkg/hostarch",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/sentry/usage",
        "//pkg/usermem",
    ],
)

package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "tmpfs",
    srcs = [
        "device.go",
        "file_regular.go",
        "fs.go",
        "inode_file.go",
        "tmpfs.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
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
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tmpfs_test",
    size = "small",
    srcs = ["file_test.go"],
    embed = [":tmpfs"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "tmpfs_state",
    srcs = [
        "file_regular.go",
        "fs.go",
        "inode_file.go",
        "tmpfs.go",
    ],
    out = "tmpfs_state.go",
    package = "tmpfs",
)

go_library(
    name = "tmpfs",
    srcs = [
        "device.go",
        "file_regular.go",
        "fs.go",
        "inode_file.go",
        "tmpfs.go",
        "tmpfs_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tmpfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/tcpip/transport/unix",
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
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/platform",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
    ],
)

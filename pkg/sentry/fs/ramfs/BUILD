package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "ramfs_state",
    srcs = [
        "dir.go",
        "file.go",
        "ramfs.go",
        "socket.go",
        "symlink.go",
    ],
    out = "ramfs_state.go",
    package = "ramfs",
)

go_library(
    name = "ramfs",
    srcs = [
        "dir.go",
        "file.go",
        "ramfs.go",
        "ramfs_state.go",
        "socket.go",
        "symlink.go",
        "tree.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/amutex",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/anon",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
    ],
)

go_test(
    name = "ramfs_test",
    size = "small",
    srcs = ["tree_test.go"],
    embed = [":ramfs"],
    deps = [
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "tty_state",
    srcs = [
        "dir.go",
        "fs.go",
        "inode.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "slave.go",
        "terminal.go",
    ],
    out = "tty_state.go",
    package = "tty",
)

go_library(
    name = "tty",
    srcs = [
        "dir.go",
        "fs.go",
        "inode.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "slave.go",
        "terminal.go",
        "tty_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/fs/tty",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/refs",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/usermem",
        "//pkg/state",
        "//pkg/syserror",
        "//pkg/tcpip/transport/unix",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tty_test",
    size = "small",
    srcs = ["tty_test.go"],
    embed = [":tty"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/usermem",
    ],
)

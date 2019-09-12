load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")

go_library(
    name = "tty",
    srcs = [
        "dir.go",
        "fs.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "slave.go",
        "terminal.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/tty",
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
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
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

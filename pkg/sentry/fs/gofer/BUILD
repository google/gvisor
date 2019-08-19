load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "gofer",
    srcs = [
        "attr.go",
        "cache_policy.go",
        "context_file.go",
        "device.go",
        "file.go",
        "file_state.go",
        "fs.go",
        "handles.go",
        "inode.go",
        "inode_state.go",
        "path.go",
        "session.go",
        "session_state.go",
        "socket.go",
        "util.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fs/gofer",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fd",
        "//pkg/log",
        "//pkg/metric",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fdpipe",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/host",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/safemem",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usermem",
        "//pkg/syserr",
        "//pkg/syserror",
        "//pkg/unet",
        "//pkg/waiter",
    ],
)

go_test(
    name = "gofer_test",
    size = "small",
    srcs = ["gofer_test.go"],
    embed = [":gofer"],
    deps = [
        "//pkg/p9",
        "//pkg/p9/p9test",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
    ],
)

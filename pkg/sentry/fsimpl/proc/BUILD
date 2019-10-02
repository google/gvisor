load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "proc",
    srcs = [
        "filesystems.go",
        "loadavg.go",
        "meminfo.go",
        "mounts.go",
        "net.go",
        "proc.go",
        "stat.go",
        "sys.go",
        "task.go",
        "version.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/proc",
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/log",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/inet",
        "//pkg/sentry/kernel",
        "//pkg/sentry/limits",
        "//pkg/sentry/mm",
        "//pkg/sentry/socket",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
    ],
)

go_test(
    name = "proc_test",
    size = "small",
    srcs = ["net_test.go"],
    embed = [":proc"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/inet",
    ],
)

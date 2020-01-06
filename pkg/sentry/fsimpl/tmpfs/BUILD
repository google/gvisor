load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "tmpfs",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentry",
        "Linker": "*dentry",
    },
)

go_library(
    name = "tmpfs",
    srcs = [
        "dentry_list.go",
        "directory.go",
        "filesystem.go",
        "named_pipe.go",
        "regular_file.go",
        "symlink.go",
        "tmpfs.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs",
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usage",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "benchmark_test",
    size = "small",
    srcs = ["benchmark_test.go"],
    deps = [
        ":tmpfs",
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/refs",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

go_test(
    name = "tmpfs_test",
    size = "small",
    srcs = [
        "pipe_test.go",
        "regular_file_test.go",
    ],
    embed = [":tmpfs"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

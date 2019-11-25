load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "memfs",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentry",
        "Linker": "*dentry",
    },
)

go_library(
    name = "memfs",
    srcs = [
        "dentry_list.go",
        "directory.go",
        "filesystem.go",
        "memfs.go",
        "named_pipe.go",
        "regular_file.go",
        "symlink.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/fsimpl/memfs",
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
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
        ":memfs",
        "//pkg/abi/linux",
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
    name = "memfs_test",
    size = "small",
    srcs = ["pipe_test.go"],
    embed = [":memfs"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
    ],
)

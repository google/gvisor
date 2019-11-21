load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "vfs",
    srcs = [
        "context.go",
        "debug.go",
        "dentry.go",
        "file_description.go",
        "file_description_impl_util.go",
        "filesystem.go",
        "filesystem_impl_util.go",
        "filesystem_type.go",
        "mount.go",
        "mount_unsafe.go",
        "options.go",
        "permissions.go",
        "resolving_path.go",
        "syscalls.go",
        "testutil.go",
        "vfs.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/sentry/vfs",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/fspath",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/usermem",
        "//pkg/syncutil",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

go_test(
    name = "vfs_test",
    size = "small",
    srcs = [
        "file_description_impl_util_test.go",
        "mount_test.go",
    ],
    embed = [":vfs"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
    ],
)

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

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
        "filesystem_type.go",
        "mount.go",
        "mount_unsafe.go",
        "options.go",
        "permissions.go",
        "resolving_path.go",
        "syscalls.go",
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
        "//pkg/syserror",
        "//pkg/waiter",
        "//third_party/gvsync",
    ],
)

go_test(
    name = "vfs_test",
    size = "small",
    srcs = [
        "mount_test.go",
    ],
    embed = [":vfs"],
)

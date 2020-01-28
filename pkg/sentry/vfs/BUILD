load("//tools:defs.bzl", "go_library", "go_test")

licenses(["notice"])

go_library(
    name = "vfs",
    srcs = [
        "anonfs.go",
        "context.go",
        "debug.go",
        "dentry.go",
        "device.go",
        "file_description.go",
        "file_description_impl_util.go",
        "filesystem.go",
        "filesystem_impl_util.go",
        "filesystem_type.go",
        "mount.go",
        "mount_unsafe.go",
        "options.go",
        "pathname.go",
        "permissions.go",
        "resolving_path.go",
        "vfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/sentry/arch",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
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
    library = ":vfs",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

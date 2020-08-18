load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "kernfs",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "Dentry",
    },
)

go_template_instance(
    name = "slot_list",
    out = "slot_list.go",
    package = "kernfs",
    prefix = "slot",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*slot",
        "Linker": "*slot",
    },
)

go_library(
    name = "kernfs",
    srcs = [
        "dynamic_bytes_file.go",
        "fd_impl_util.go",
        "filesystem.go",
        "fstree.go",
        "inode_impl_util.go",
        "kernfs.go",
        "slot_list.go",
        "symlink.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "kernfs_test",
    size = "small",
    srcs = ["kernfs_test.go"],
    deps = [
        ":kernfs",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

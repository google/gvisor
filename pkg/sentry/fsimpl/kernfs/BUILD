load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "kernfs",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Dentry",
        "Linker": "*Dentry",
    },
)

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

go_template_instance(
    name = "static_directory_refs",
    out = "static_directory_refs.go",
    package = "kernfs",
    prefix = "StaticDirectory",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "StaticDirectory",
    },
)

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "kernfs_test",
    prefix = "dir",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "dir",
    },
)

go_template_instance(
    name = "readonly_dir_refs",
    out = "readonly_dir_refs.go",
    package = "kernfs_test",
    prefix = "readonlyDir",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "readonlyDir",
    },
)

go_template_instance(
    name = "synthetic_directory_refs",
    out = "synthetic_directory_refs.go",
    package = "kernfs",
    prefix = "syntheticDirectory",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "syntheticDirectory",
    },
)

go_library(
    name = "kernfs",
    srcs = [
        "dentry_list.go",
        "dynamic_bytes_file.go",
        "fd_impl_util.go",
        "filesystem.go",
        "fstree.go",
        "inode_impl_util.go",
        "kernfs.go",
        "mmap_util.go",
        "save_restore.go",
        "slot_list.go",
        "static_directory_refs.go",
        "symlink.go",
        "synthetic_directory.go",
        "synthetic_directory_refs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
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
    srcs = [
        "dir_refs.go",
        "kernfs_test.go",
        "readonly_dir_refs.go",
    ],
    deps = [
        ":kernfs",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

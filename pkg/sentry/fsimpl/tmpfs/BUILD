load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

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

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "tmpfs",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
    },
)

go_template_instance(
    name = "inode_refs",
    out = "inode_refs.go",
    package = "tmpfs",
    prefix = "inode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "inode",
    },
)

go_library(
    name = "tmpfs",
    srcs = [
        "dentry_list.go",
        "device_file.go",
        "directory.go",
        "filesystem.go",
        "fstree.go",
        "inode_refs.go",
        "named_pipe.go",
        "regular_file.go",
        "save_restore.go",
        "socket_file.go",
        "symlink.go",
        "tmpfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sentry/vfs/memxattr",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

go_test(
    name = "benchmark_test",
    size = "small",
    srcs = ["benchmark_test.go"],
    deps = [
        ":tmpfs",
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/fspath",
        "//pkg/refs",
        "//pkg/sentry/contexttest",
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
        "stat_test.go",
        "tmpfs_test.go",
    ],
    library = ":tmpfs",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
    ],
)

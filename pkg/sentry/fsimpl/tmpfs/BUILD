load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

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
    template = "//pkg/refs:refs_template",
    types = {
        "T": "inode",
    },
)

declare_mutex(
    name = "inode_mutex",
    out = "inode_mutex.go",
    package = "tmpfs",
    prefix = "inode",
)

declare_mutex(
    name = "pages_used_mutex",
    out = "pages_used_mutex.go",
    package = "tmpfs",
    prefix = "pagesUsed",
)

declare_mutex(
    name = "iter_mutex",
    out = "iter_mutex.go",
    package = "tmpfs",
    prefix = "iter",
)

declare_rwmutex(
    name = "filesystem_mutex",
    out = "filesystem_mutex.go",
    package = "tmpfs",
    prefix = "filesystem",
)

go_library(
    name = "tmpfs",
    srcs = [
        "dentry_list.go",
        "device_file.go",
        "directory.go",
        "filesystem.go",
        "filesystem_mutex.go",
        "fstree.go",
        "inode_mutex.go",
        "inode_refs.go",
        "iter_mutex.go",
        "named_pipe.go",
        "pages_used_mutex.go",
        "regular_file.go",
        "save_restore.go",
        "socket_file.go",
        "symlink.go",
        "tmpfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/fsutil",
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
        "//pkg/sync/locking",
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
        "//pkg/fspath",
        "//pkg/refs",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
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
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
    ],
)

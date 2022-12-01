load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

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
    template = "//pkg/refs:refs_template",
    types = {
        "T": "StaticDirectory",
    },
)

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "kernfs_test",
    prefix = "dir",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "dir",
    },
)

go_template_instance(
    name = "readonly_dir_refs",
    out = "readonly_dir_refs.go",
    package = "kernfs_test",
    prefix = "readonlyDir",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "readonlyDir",
    },
)

go_template_instance(
    name = "synthetic_directory_refs",
    out = "synthetic_directory_refs.go",
    package = "kernfs",
    prefix = "syntheticDirectory",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "syntheticDirectory",
    },
)

declare_rwmutex(
    name = "filesystem_mutex",
    out = "filesystem_mutex.go",
    package = "kernfs",
    prefix = "filesystem",
)

declare_mutex(
    name = "deferred_dec_refs_mutex",
    out = "deferred_dec_refs_mutex.go",
    package = "kernfs",
    prefix = "deferredDecRefs",
)

go_library(
    name = "kernfs",
    srcs = [
        "deferred_dec_refs_mutex.go",
        "dentry_list.go",
        "dynamic_bytes_file.go",
        "fd_impl_util.go",
        "filesystem.go",
        "filesystem_mutex.go",
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
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
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
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

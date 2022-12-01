load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

licenses(["notice"])

declare_mutex(
    name = "dir_mutex",
    out = "dir_mutex.go",
    nested_lock_names = [
        "new",
        "replaced",
        "child",
    ],
    package = "overlay",
    prefix = "dir",
)

declare_mutex(
    name = "dev_mutex",
    out = "dev_mutex.go",
    package = "overlay",
    prefix = "dev",
)

declare_mutex(
    name = "dir_cache_mutex",
    out = "dir_cache_mutex.go",
    package = "overlay",
    prefix = "dirInoCache",
)

declare_mutex(
    name = "reg_file_fd_mutex",
    out = "req_file_fd_mutex.go",
    package = "overlay",
    prefix = "regularFileFD",
)

declare_mutex(
    name = "dir_fd_mutex",
    out = "dir_fd_mutex.go",
    package = "overlay",
    prefix = "directoryFD",
)

declare_rwmutex(
    name = "rename_rwmutex",
    out = "rename_rwmutex.go",
    package = "overlay",
    prefix = "rename",
)

declare_rwmutex(
    name = "data_rwmutex",
    out = "data_rwmutex.go",
    package = "overlay",
    prefix = "data",
)

declare_mutex(
    name = "maps_mutex",
    out = "maps_mutex.go",
    package = "overlay",
    prefix = "maps",
)

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "overlay",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
    },
)

go_library(
    name = "overlay",
    srcs = [
        "copy_up.go",
        "data_rwmutex.go",
        "dev_mutex.go",
        "dir_cache_mutex",
        "dir_fd_mutex.go",
        "dir_mutex.go",
        "directory.go",
        "filesystem.go",
        "fstree.go",
        "maps_mutex.go",
        "overlay.go",
        "regular_file.go",
        "rename_rwmutex.go",
        "req_file_fd_mutex.go",
        "save_restore.go",
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
        "//pkg/sentry/arch",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

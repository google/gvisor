load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex")

package(licenses = ["notice"])

go_library(
    name = "fs",
    srcs = [
        "attr.go",
        "context.go",
        "copy_up.go",
        "dentry.go",
        "dirent.go",
        "dirent_cache.go",
        "dirent_cache_limiter.go",
        "dirent_list.go",
        "dirent_state.go",
        "event_list.go",
        "file.go",
        "file_operations.go",
        "file_overlay.go",
        "file_state.go",
        "filesystems.go",
        "flags.go",
        "fs.go",
        "inode.go",
        "inode_inotify.go",
        "inode_operations.go",
        "inode_overlay.go",
        "inotify.go",
        "inotify_event.go",
        "inotify_event_mutex.go",
        "inotify_mutex.go",
        "inotify_watch.go",
        "mock.go",
        "mount.go",
        "mount_overlay.go",
        "mounts.go",
        "namespace_mutex.go",
        "offset.go",
        "overlay.go",
        "path.go",
        "restore.go",
        "save.go",
        "seek.go",
        "splice.go",
        "sync.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/uniqueid",
        "//pkg/sentry/usage",
        "//pkg/state",
        "//pkg/sync",
        "//pkg/sync/locking",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_template_instance(
    name = "dirent_list",
    out = "dirent_list.go",
    package = "fs",
    prefix = "dirent",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*Dirent",
        "Element": "*Dirent",
    },
)

go_template_instance(
    name = "event_list",
    out = "event_list.go",
    package = "fs",
    prefix = "event",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*Event",
        "Element": "*Event",
    },
)

declare_mutex(
    name = "namespace_mutex",
    out = "namespace_mutex.go",
    package = "fs",
    prefix = "namespace",
)

declare_mutex(
    name = "inotify_event_mutex",
    out = "inotify_event_mutex.go",
    package = "fs",
    prefix = "inotifyEvent",
)

declare_mutex(
    name = "inotify_mutex",
    out = "inotify_mutex.go",
    package = "fs",
    prefix = "inotify",
)

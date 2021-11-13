load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

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
        "inotify_watch.go",
        "mock.go",
        "mount.go",
        "mount_overlay.go",
        "mounts.go",
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
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/p9",
        "//pkg/refs",
        "//pkg/secio",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs/lock",
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

go_test(
    name = "fs_x_test",
    size = "small",
    srcs = [
        "copy_up_test.go",
        "file_overlay_test.go",
        "inode_overlay_test.go",
        "mounts_test.go",
    ],
    deps = [
        ":fs",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/fs/ramfs",
        "//pkg/sentry/fs/tmpfs",
        "//pkg/sentry/kernel/contexttest",
        "//pkg/sync",
        "//pkg/usermem",
    ],
)

go_test(
    name = "fs_test",
    size = "small",
    srcs = [
        "dirent_cache_test.go",
        "dirent_refs_test.go",
        "mount_test.go",
        "path_test.go",
    ],
    library = ":fs",
    deps = [
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

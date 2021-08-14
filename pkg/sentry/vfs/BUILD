load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "epoll_interest_list",
    out = "epoll_interest_list.go",
    package = "vfs",
    prefix = "epollInterest",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*epollInterest",
        "Linker": "*epollInterest",
    },
)

go_template_instance(
    name = "event_list",
    out = "event_list.go",
    package = "vfs",
    prefix = "event",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Event",
        "Linker": "*Event",
    },
)

go_template_instance(
    name = "file_description_refs",
    out = "file_description_refs.go",
    package = "vfs",
    prefix = "FileDescription",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "FileDescription",
    },
)

go_template_instance(
    name = "mount_namespace_refs",
    out = "mount_namespace_refs.go",
    package = "vfs",
    prefix = "MountNamespace",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "MountNamespace",
    },
)

go_template_instance(
    name = "filesystem_refs",
    out = "filesystem_refs.go",
    package = "vfs",
    prefix = "Filesystem",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "Filesystem",
    },
)

go_library(
    name = "vfs",
    srcs = [
        "anonfs.go",
        "context.go",
        "debug.go",
        "dentry.go",
        "device.go",
        "epoll.go",
        "epoll_interest_list.go",
        "event_list.go",
        "file_description.go",
        "file_description_impl_util.go",
        "file_description_refs.go",
        "filesystem.go",
        "filesystem_impl_util.go",
        "filesystem_refs.go",
        "filesystem_type.go",
        "inotify.go",
        "lock.go",
        "mount.go",
        "mount_namespace_refs.go",
        "mount_unsafe.go",
        "opath.go",
        "options.go",
        "pathname.go",
        "permissions.go",
        "resolving_path.go",
        "save_restore.go",
        "vfs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/fspath",
        "//pkg/gohacks",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/limits",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/uniqueid",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
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
        "//pkg/errors/linuxerr",
        "//pkg/sentry/contexttest",
        "//pkg/sync",
        "//pkg/usermem",
    ],
)

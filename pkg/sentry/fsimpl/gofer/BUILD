load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_template_instance(
    name = "inode_refs",
    out = "inode_refs.go",
    package = "gofer",
    prefix = "inode",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "inode",
    },
)

go_template_instance(
    name = "string_list",
    out = "string_list.go",
    package = "gofer",
    prefix = "string",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*stringListElem",
        "Linker": "*stringListElem",
    },
)

go_template_instance(
    name = "dentry_list",
    out = "dentry_list.go",
    package = "gofer",
    prefix = "dentry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*dentryListElem",
        "Linker": "*dentryListElem",
    },
)

go_template_instance(
    name = "special_fd_list",
    out = "special_fd_list.go",
    package = "gofer",
    prefix = "specialFD",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*specialFileFD",
        "Linker": "*specialFileFD",
    },
)

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "gofer",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
        "Filesystem": "filesystem",
    },
)

go_library(
    name = "gofer",
    srcs = [
        "dentry_list.go",
        "directfs_inode.go",
        "directory.go",
        "filesystem.go",
        "fstree.go",
        "gofer.go",
        "handle.go",
        "host_named_pipe.go",
        "inode_impl.go",
        "inode_refs.go",
        "lisafs_inode.go",
        "regular_file.go",
        "revalidate.go",
        "save_restore.go",
        "socket.go",
        "special_fd_list.go",
        "special_file.go",
        "string_list.go",
        "symlink.go",
        "time.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fd",
        "//pkg/fdnotifier",
        "//pkg/fspath",
        "//pkg/fsutil",
        "//pkg/hostarch",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/metric",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/host",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsmetric",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/pipe",
        "//pkg/sentry/ktime",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/platform",
        "//pkg/sentry/socket/control",
        "//pkg/sentry/socket/unix",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/unet",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "gofer_test",
    srcs = ["gofer_test.go"],
    library = ":gofer",
    deps = [
        "//pkg/abi/linux",
        "//pkg/lisafs",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/ktime",
        "//pkg/sentry/pgalloc",
    ],
)

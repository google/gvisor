load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_template_instance(
    name = "fstree",
    out = "fstree.go",
    package = "erofs",
    prefix = "generic",
    template = "//pkg/sentry/vfs/genericfstree:generic_fstree",
    types = {
        "Dentry": "dentry",
        "Filesystem": "filesystem",
    },
)

go_template_instance(
    name = "dentry_refs",
    out = "dentry_refs.go",
    package = "erofs",
    prefix = "dentry",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "dentry",
    },
)

go_template_instance(
    name = "inode_refs",
    out = "inode_refs.go",
    package = "erofs",
    prefix = "inode",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "inode",
    },
)

go_library(
    name = "erofs",
    srcs = [
        "dentry_refs.go",
        "directory.go",
        "erofs.go",
        "filesystem.go",
        "fstree.go",
        "inode_refs.go",
        "regular_file.go",
        "save_restore.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/cleanup",
        "//pkg/context",
        "//pkg/erofs",
        "//pkg/errors/linuxerr",
        "//pkg/fspath",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/lock",
        "//pkg/sentry/fsutil",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/socket/unix/transport",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
    ],
)

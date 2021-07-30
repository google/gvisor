load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "root_inode_refs",
    out = "root_inode_refs.go",
    package = "mqfs",
    prefix = "rootInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "rootInode",
    },
)

go_library(
    name = "mqfs",
    srcs = [
        "mqfs.go",
        "root.go",
        "queue.go",
        "registry.go",
        "root_inode_refs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/refsvfs2",
        "//pkg/sentry/fs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/ipc",
        "//pkg/sentry/kernel/mq",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

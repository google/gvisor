load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "root_inode_refs",
    out = "root_inode_refs.go",
    package = "devpts",
    prefix = "rootInode",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "rootInode",
    },
)

go_library(
    name = "devpts",
    srcs = [
        "devpts.go",
        "line_discipline.go",
        "master.go",
        "queue.go",
        "replica.go",
        "root_inode_refs.go",
        "terminal.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/unimpl",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "devpts_test",
    size = "small",
    srcs = ["devpts_test.go"],
    library = ":devpts",
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/contexttest",
        "//pkg/usermem",
    ],
)

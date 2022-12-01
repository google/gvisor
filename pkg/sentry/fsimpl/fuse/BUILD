load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

licenses(["notice"])

go_template_instance(
    name = "request_list",
    out = "request_list.go",
    package = "fuse",
    prefix = "request",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Request",
        "Linker": "*Request",
    },
)

go_template_instance(
    name = "inode_refs",
    out = "inode_refs.go",
    package = "fuse",
    prefix = "inode",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "inode",
    },
)

go_library(
    name = "fuse",
    srcs = [
        "connection.go",
        "connection_control.go",
        "dev.go",
        "dev_state.go",
        "directory.go",
        "file.go",
        "fusefs.go",
        "inode_refs.go",
        "read_write.go",
        "register.go",
        "regular_file.go",
        "request_list.go",
        "request_response.go",
    ],
    marshal = True,
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/log",
        "//pkg/marshal",
        "//pkg/marshal/primitive",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fuse_test",
    size = "small",
    srcs = [
        "connection_test.go",
        "dev_test.go",
        "utils_test.go",
    ],
    library = ":fuse",
    deps = [
        "//pkg/abi/linux",
        "//pkg/errors/linuxerr",
        "//pkg/marshal/primitive",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/usermem",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

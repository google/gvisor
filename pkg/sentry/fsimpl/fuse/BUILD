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

go_library(
    name = "fuse",
    srcs = [
        "connection.go",
        "dev.go",
        "directory.go",
        "file.go",
        "fusefs.go",
        "init.go",
        "read_write.go",
        "register.go",
        "regular_file.go",
        "request_list.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/safemem",
        "//pkg/sentry/fsimpl/devtmpfs",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
        "//tools/go_marshal/marshal",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "fuse_test",
    size = "small",
    srcs = ["dev_test.go"],
    library = ":fuse",
    deps = [
        "//pkg/abi/linux",
        "//pkg/sentry/fsimpl/testutil",
        "//pkg/sentry/kernel",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
        "//tools/go_marshal/marshal",
    ],
)

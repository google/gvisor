load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "buffer_list",
    out = "buffer_list.go",
    package = "pipe",
    prefix = "buffer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*buffer",
        "Linker": "*buffer",
    },
)

go_library(
    name = "pipe",
    srcs = [
        "buffer.go",
        "buffer_list.go",
        "device.go",
        "node.go",
        "pipe.go",
        "pipe_util.go",
        "reader.go",
        "reader_writer.go",
        "vfs.go",
        "writer.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/context",
        "//pkg/safemem",
        "//pkg/sentry/arch",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "pipe_test",
    size = "small",
    srcs = [
        "buffer_test.go",
        "node_test.go",
        "pipe_test.go",
    ],
    library = ":pipe",
    deps = [
        "//pkg/context",
        "//pkg/sentry/contexttest",
        "//pkg/sentry/fs",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

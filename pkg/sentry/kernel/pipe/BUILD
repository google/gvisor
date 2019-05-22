package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

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
        "reader.go",
        "reader_writer.go",
        "writer.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/pipe",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/amutex",
        "//pkg/sentry/arch",
        "//pkg/sentry/context",
        "//pkg/sentry/device",
        "//pkg/sentry/fs",
        "//pkg/sentry/fs/fsutil",
        "//pkg/sentry/safemem",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
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
    embed = [":pipe"],
    deps = [
        "//pkg/sentry/context",
        "//pkg/sentry/context/contexttest",
        "//pkg/sentry/fs",
        "//pkg/sentry/usermem",
        "//pkg/syserror",
        "//pkg/waiter",
    ],
)

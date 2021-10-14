load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "message_list",
    out = "message_list.go",
    package = "mq",
    prefix = "msg",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Message",
        "Linker": "*Message",
    },
)

go_library(
    name = "mq",
    srcs = [
        "message_list.go",
        "mq.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)

load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "message_list",
    out = "message_list.go",
    package = "msgqueue",
    prefix = "msg",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*Message",
        "Linker": "*Message",
    },
)

go_library(
    name = "msgqueue",
    srcs = [
        "message_list.go",
        "msgqueue.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/fs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/kernel/ipc",
        "//pkg/sentry/kernel/time",
        "//pkg/sync",
        "//pkg/waiter",
    ],
)

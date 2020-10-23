load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "transport_message_list",
    out = "transport_message_list.go",
    package = "transport",
    prefix = "message",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*message",
        "Linker": "*message",
    },
)

go_template_instance(
    name = "queue_refs",
    out = "queue_refs.go",
    package = "transport",
    prefix = "queue",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "queue",
    },
)

go_library(
    name = "transport",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "queue.go",
        "queue_refs.go",
        "transport_message_list.go",
        "unix.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)

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

go_library(
    name = "transport",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "queue.go",
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
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)

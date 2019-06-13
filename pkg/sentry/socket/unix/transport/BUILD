package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

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
    importpath = "gvisor.dev/gvisor/pkg/sentry/socket/unix/transport",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/ilist",
        "//pkg/refs",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/waiter",
    ],
)

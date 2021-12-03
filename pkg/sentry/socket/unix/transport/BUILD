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

go_template_instance(
    name = "host_connected_endpoint_refs",
    out = "host_connected_endpoint_refs.go",
    package = "transport",
    prefix = "HostConnectedEndpoint",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "HostConnectedEndpoint",
    },
)

go_library(
    name = "transport",
    srcs = [
        "connectioned.go",
        "connectioned_state.go",
        "connectionless.go",
        "connectionless_state.go",
        "host.go",
        "host_connected_endpoint_refs.go",
        "host_iovec.go",
        "host_unsafe.go",
        "queue.go",
        "queue_refs.go",
        "save_restore.go",
        "transport_message_list.go",
        "unix.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/fdnotifier",
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sentry/hostfd",
        "//pkg/sentry/inet",
        "//pkg/sentry/uniqueid",
        "//pkg/sync",
        "//pkg/syserr",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/unet",
        "//pkg/waiter",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

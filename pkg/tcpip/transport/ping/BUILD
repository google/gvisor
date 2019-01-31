package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

go_template_instance(
    name = "ping_packet_list",
    out = "ping_packet_list.go",
    package = "ping",
    prefix = "pingPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*pingPacket",
        "Linker": "*pingPacket",
    },
)

go_library(
    name = "ping",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "ping_packet_list.go",
        "protocol.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/ping",
    imports = ["gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

filegroup(
    name = "autogen",
    srcs = [
        "ping_packet_list.go",
    ],
    visibility = ["//:sandbox"],
)

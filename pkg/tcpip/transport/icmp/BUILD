package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

go_template_instance(
    name = "icmp_packet_list",
    out = "icmp_packet_list.go",
    package = "icmp",
    prefix = "icmpPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*icmpPacket",
        "Linker": "*icmpPacket",
    },
)

go_library(
    name = "icmp",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "icmp_packet_list.go",
        "protocol.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/icmp",
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
        "icmp_packet_list.go",
    ],
    visibility = ["//:sandbox"],
)

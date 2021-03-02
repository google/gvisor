load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

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
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
    ],
)

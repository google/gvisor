load("//tools:defs.bzl", "go_library", "go_test")
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
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/log",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
        "//pkg/tcpip/transport/internal/network",
        "//pkg/tcpip/transport/raw",
        "//pkg/tcpip/transport/tcp",
        "//pkg/waiter",
    ],
)

go_test(
    name = "icmp_x_test",
    size = "small",
    srcs = ["icmp_test.go"],
    deps = [
        ":icmp",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/testing/context",
        "//pkg/waiter",
    ],
)

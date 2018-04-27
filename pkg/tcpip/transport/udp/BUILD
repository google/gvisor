package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "udp_state",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "udp_packet_list.go",
    ],
    out = "udp_state.go",
    imports = ["gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"],
    package = "udp",
)

go_template_instance(
    name = "udp_packet_list",
    out = "udp_packet_list.go",
    package = "udp",
    prefix = "udpPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*udpPacket",
    },
)

go_library(
    name = "udp",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "protocol.go",
        "udp_packet_list.go",
        "udp_state.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/udp",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sleep",
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

go_test(
    name = "udp_x_test",
    size = "small",
    srcs = ["udp_test.go"],
    deps = [
        ":udp",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/waiter",
    ],
)

filegroup(
    name = "autogen",
    srcs = [
        "udp_packet_list.go",
    ],
    visibility = ["//:sandbox"],
)

load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "udp_packet_list",
    out = "udp_packet_list.go",
    package = "udp",
    prefix = "udpPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*udpPacket",
        "Linker": "*udpPacket",
    },
)

go_library(
    name = "udp",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "forwarder.go",
        "protocol.go",
        "udp_packet_list.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
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
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/icmp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

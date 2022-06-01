load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "raw_packet_list",
    out = "raw_packet_list.go",
    package = "raw",
    prefix = "rawPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*rawPacket",
        "Linker": "*rawPacket",
    },
)

go_library(
    name = "raw",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "protocol.go",
        "raw_packet_list.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/buffer",
        "//pkg/log",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport",
        "//pkg/tcpip/transport/internal/network",
        "//pkg/tcpip/transport/internal/noop",
        "//pkg/tcpip/transport/packet",
        "//pkg/waiter",
    ],
)

go_test(
    name = "raw_x_test",
    size = "small",
    srcs = ["raw_test.go"],
    deps = [
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/testing/context",
        "//pkg/tcpip/transport/udp",
    ],
)

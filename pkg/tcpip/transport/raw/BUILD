load("//tools:defs.bzl", "go_library")
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
        "//pkg/log",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/network",
        "//pkg/tcpip/transport/packet",
        "//pkg/waiter",
    ],
)

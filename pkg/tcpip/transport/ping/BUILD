package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "ping_state",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "ping_packet_list.go",
    ],
    out = "ping_state.go",
    imports = ["gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"],
    package = "ping",
)

go_template_instance(
    name = "ping_packet_list",
    out = "ping_packet_list.go",
    package = "ping",
    prefix = "pingPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*pingPacket",
    },
)

go_library(
    name = "ping",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "ping_packet_list.go",
        "ping_state.go",
        "protocol.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/ping",
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

filegroup(
    name = "autogen",
    srcs = [
        "ping_packet_list.go",
    ],
    visibility = ["//:sandbox"],
)

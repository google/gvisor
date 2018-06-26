package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_stateify")

go_stateify(
    name = "tcp_state",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
        "rcv.go",
        "segment_heap.go",
        "snd.go",
        "tcp_segment_list.go",
    ],
    out = "tcp_state.go",
    package = "tcp",
)

go_template_instance(
    name = "tcp_segment_list",
    out = "tcp_segment_list.go",
    package = "tcp",
    prefix = "segment",
    template = "//pkg/ilist:generic_list",
    types = {
        "Linker": "*segment",
    },
)

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "connect.go",
        "endpoint.go",
        "endpoint_state.go",
        "forwarder.go",
        "protocol.go",
        "rcv.go",
        "sack.go",
        "segment.go",
        "segment_heap.go",
        "segment_queue.go",
        "snd.go",
        "tcp_segment_list.go",
        "tcp_state.go",
        "timer.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/sleep",
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tmutex",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tcp_test",
    size = "small",
    srcs = [
        "dual_stack_test.go",
        "tcp_sack_test.go",
        "tcp_test.go",
        "tcp_timestamp_test.go",
    ],
    deps = [
        ":tcp",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/waiter",
    ],
)

filegroup(
    name = "autogen",
    srcs = [
        "tcp_segment_list.go",
    ],
    visibility = ["//:sandbox"],
)

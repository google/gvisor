package(licenses = ["notice"])

load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_template_instance(
    name = "tcp_segment_list",
    out = "tcp_segment_list.go",
    package = "tcp",
    prefix = "segment",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*segment",
        "Linker": "*segment",
    },
)

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "connect.go",
        "cubic.go",
        "endpoint.go",
        "endpoint_state.go",
        "forwarder.go",
        "protocol.go",
        "rcv.go",
        "reno.go",
        "sack.go",
        "sack_scoreboard.go",
        "segment.go",
        "segment_heap.go",
        "segment_queue.go",
        "segment_state.go",
        "snd.go",
        "snd_state.go",
        "tcp_segment_list.go",
        "timer.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp",
    imports = ["gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/tmutex",
        "//pkg/waiter",
        "@com_github_google_btree//:go_default_library",
    ],
)

filegroup(
    name = "autogen",
    srcs = [
        "tcp_segment_list.go",
    ],
    visibility = ["//:sandbox"],
)

go_test(
    name = "tcp_test",
    size = "small",
    srcs = [
        "dual_stack_test.go",
        "sack_scoreboard_test.go",
        "tcp_sack_test.go",
        "tcp_test.go",
        "tcp_timestamp_test.go",
    ],
    # FIXME(b/68809571)
    tags = ["flaky"],
    deps = [
        ":tcp",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/waiter",
    ],
)

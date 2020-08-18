load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "tcp_segment_list",
    out = "tcp_segment_list.go",
    package = "tcp",
    prefix = "segment",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*segment",
        "ElementMapper": "segmentMapper",
        "Linker": "*segmentEntry",
    },
)

go_template_instance(
    name = "tcp_endpoint_list",
    out = "tcp_endpoint_list.go",
    package = "tcp",
    prefix = "endpoint",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*endpoint",
        "Linker": "*endpoint",
    },
)

go_template_instance(
    name = "tcp_rack_segment_list",
    out = "tcp_rack_segment_list.go",
    package = "tcp",
    prefix = "rackSegment",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*segment",
        "ElementMapper": "rackSegmentMapper",
        "Linker": "*rackSegmentEntry",
    },
)

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "connect.go",
        "connect_unsafe.go",
        "cubic.go",
        "cubic_state.go",
        "dispatcher.go",
        "endpoint.go",
        "endpoint_state.go",
        "forwarder.go",
        "protocol.go",
        "rack.go",
        "rack_state.go",
        "rcv.go",
        "rcv_state.go",
        "reno.go",
        "sack.go",
        "sack_scoreboard.go",
        "segment.go",
        "segment_heap.go",
        "segment_queue.go",
        "segment_state.go",
        "segment_unsafe.go",
        "snd.go",
        "snd_state.go",
        "tcp_endpoint_list.go",
        "tcp_rack_segment_list.go",
        "tcp_segment_list.go",
        "timer.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/waiter",
        "@com_github_google_btree//:go_default_library",
    ],
)

go_test(
    name = "tcp_x_test",
    size = "medium",
    srcs = [
        "dual_stack_test.go",
        "sack_scoreboard_test.go",
        "tcp_noracedetector_test.go",
        "tcp_rack_test.go",
        "tcp_sack_test.go",
        "tcp_test.go",
        "tcp_timestamp_test.go",
    ],
    shard_count = 10,
    deps = [
        ":tcp",
        "//pkg/sync",
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
        "//pkg/test/testutil",
        "//pkg/waiter",
    ],
)

go_test(
    name = "rcv_test",
    size = "small",
    srcs = ["rcv_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
    ],
)

go_test(
    name = "tcp_test",
    size = "small",
    srcs = ["timer_test.go"],
    library = ":tcp",
    deps = ["//pkg/sleep"],
)

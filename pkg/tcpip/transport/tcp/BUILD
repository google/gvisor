load("//tools:defs.bzl", "go_library", "go_test", "more_shards")
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
        "Linker": "*segment",
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

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "connect.go",
        "connect_unsafe.go",
        "cubic.go",
        "dispatcher.go",
        "endpoint.go",
        "endpoint_state.go",
        "forwarder.go",
        "protocol.go",
        "rack.go",
        "rcv.go",
        "reno.go",
        "reno_recovery.go",
        "sack.go",
        "sack_recovery.go",
        "sack_scoreboard.go",
        "segment.go",
        "segment_heap.go",
        "segment_queue.go",
        "segment_state.go",
        "segment_unsafe.go",
        "snd.go",
        "tcp_endpoint_list.go",
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
        "//pkg/tcpip/header/parse",
        "//pkg/tcpip/internal/tcp",
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
    shard_count = more_shards,
    deps = [
        ":tcp",
        "//pkg/rand",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/link/sniffer",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/tcp/testing/context",
        "//pkg/test/testutil",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
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
    srcs = [
        "segment_test.go",
        "timer_test.go",
    ],
    library = ":tcp",
    deps = [
        "//pkg/sleep",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

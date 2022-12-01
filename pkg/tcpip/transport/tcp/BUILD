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
        "Linker": "*segment",
    },
)

go_template_instance(
    name = "tcp_segment_refs",
    out = "tcp_segment_refs.go",
    package = "tcp",
    prefix = "segment",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "segment",
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
        "tcp_segment_refs.go",
        "timer.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
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
    name = "tcp_test",
    size = "small",
    srcs = [
        "main_test.go",
        "segment_test.go",
        "timer_test.go",
    ],
    library = ":tcp",
    deps = [
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/sleep",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "snd_queue_mutex",
    out = "snd_queue_mutex.go",
    package = "tcp",
    prefix = "sndQueue",
    substrs = {
        "genericMark": "sndQueue",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "rcv_queue_mutex",
    out = "rcv_queue_mutex.go",
    package = "tcp",
    prefix = "rcvQueue",
    substrs = {
        "genericMark": "rcvQueue",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "rcv_read_mutex",
    out = "rcv_read_mutex.go",
    package = "tcp",
    prefix = "rcvRead",
    substrs = {
        "genericMark": "rcvRead",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "accept_mutex",
    out = "accept_mutex.go",
    package = "tcp",
    prefix = "accept",
    substrs = {
        "genericMark": "accept",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "last_error_mutex",
    out = "last_error_mutex.go",
    package = "tcp",
    prefix = "lastError",
    substrs = {
        "genericMark": "lastError",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "segment_queue_mutex",
    out = "segment_queue_mutex.go",
    package = "tcp",
    prefix = "segmentQueue",
    substrs = {
        "genericMark": "segmentQueue",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "ep_queue_mutex",
    out = "ep_queue_mutex.go",
    package = "tcp",
    prefix = "epQueue",
    substrs = {
        "genericMark": "epQueue",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "forwarder_mutex",
    out = "forwarder_mutex.go",
    package = "tcp",
    prefix = "forwarder",
    substrs = {
        "genericMark": "forwarder",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

go_template_instance(
    name = "forwarder_request_mutex",
    out = "forwarder_request_mutex.go",
    package = "tcp",
    prefix = "forwarderRequest",
    substrs = {
        "genericMark": "forwarderRequest",
    },
    template = "//pkg/sync/locking:generic_mutex",
)

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
    template = "//pkg/refsvfs2:refs_template",
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
        "snd_queue_mutex.go",
        "rcv_queue_mutex.go",
        "rcv_read_mutex.go",
        "accept_mutex.go",
        "last_error_mutex.go",
        "segment_queue_mutex.go",
        "ep_queue_mutex.go",
        "forwarder_mutex.go",
        "forwarder_request_mutex.go",
    ],
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/refsvfs2",
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
        "//pkg/sync/locking",
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
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/sleep",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

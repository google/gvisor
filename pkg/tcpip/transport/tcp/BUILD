load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")
load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

declare_mutex(
    name = "snd_queue_mutex",
    out = "snd_queue_mutex.go",
    package = "tcp",
    prefix = "sndQueue",
)

declare_mutex(
    name = "pending_processing_mutex",
    out = "pending_processing_mutex.go",
    package = "tcp",
    prefix = "pendingProcessing",
)

declare_mutex(
    name = "last_error_mutex",
    out = "last_error_mutex.go",
    package = "tcp",
    prefix = "lastError",
)

declare_mutex(
    name = "rcv_queue_mutex",
    out = "rcv_queue_mutex.go",
    package = "tcp",
    prefix = "rcvQueue",
)

declare_mutex(
    name = "accept_mutex",
    out = "accept_mutex.go",
    package = "tcp",
    prefix = "accept",
)

declare_mutex(
    name = "keepalive_mutex",
    out = "keepalive_mutex.go",
    package = "tcp",
    prefix = "keepalive",
)

declare_mutex(
    name = "hasher_mutex",
    out = "hasher_mutex.go",
    package = "tcp",
    prefix = "hasher",
)

declare_mutex(
    name = "forwarder_mutex",
    out = "forwarder_mutex.go",
    package = "tcp",
    prefix = "forwarder",
)

declare_mutex(
    name = "forwarder_request_mutex",
    out = "forwarder_request_mutex.go",
    package = "tcp",
    prefix = "forwarderRequest",
)

declare_mutex(
    name = "segment_queue_mutex",
    out = "segment_queue_mutex.go",
    package = "tcp",
    prefix = "segmentQueue",
)

declare_mutex(
    name = "ep_queue_mutex",
    out = "ep_queue_mutex.go",
    package = "tcp",
    prefix = "epQueue",
)

declare_mutex(
    name = "dispatcher_mutex",
    out = "dispatcher_mutex.go",
    package = "tcp",
    prefix = "dispatcher",
)

declare_mutex(
    name = "rtt_mutex",
    out = "rtt_mutex.go",
    package = "tcp",
    prefix = "rtt",
)

declare_rwmutex(
    name = "protocol_mutex",
    out = "protocol_mutex.go",
    package = "tcp",
    prefix = "protocol",
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
        "Element": "*Endpoint",
        "Linker": "*Endpoint",
    },
)

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "accept_mutex.go",
        "connect.go",
        "connect_unsafe.go",
        "cubic.go",
        "dispatcher.go",
        "dispatcher_mutex.go",
        "endpoint.go",
        "endpoint_state.go",
        "ep_queue_mutex.go",
        "forwarder.go",
        "forwarder_mutex.go",
        "forwarder_request_mutex.go",
        "hasher_mutex.go",
        "keepalive_mutex.go",
        "last_error_mutex.go",
        "pending_processing_mutex.go",
        "protocol.go",
        "protocol_mutex.go",
        "rack.go",
        "rcv.go",
        "rcv_queue_mutex.go",
        "reno.go",
        "reno_recovery.go",
        "rtt_mutex.go",
        "sack.go",
        "sack_recovery.go",
        "sack_scoreboard.go",
        "segment.go",
        "segment_heap.go",
        "segment_queue.go",
        "segment_queue_mutex.go",
        "segment_state.go",
        "segment_unsafe.go",
        "snd.go",
        "snd_queue_mutex.go",
        "state.go",
        "tcp_endpoint_list.go",
        "tcp_segment_list.go",
        "tcp_segment_refs.go",
        "timer.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/sync/locking",
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
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "tcp_test",
    size = "small",
    srcs = [
        "cubic_test.go",
        "main_test.go",
        "segment_test.go",
        "timer_test.go",
    ],
    library = ":tcp",
    deps = [
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

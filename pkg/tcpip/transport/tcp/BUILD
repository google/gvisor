load("//tools:defs.bzl", "go_library", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(licenses = ["notice"])

declare_mutex("tcp", "pending_processing_mutex", "pendingProcessing")

declare_mutex("tcp", "rtt_mutex", "rtt")

declare_mutex("tcp", "keepalive_mutex", "keepalive")

declare_mutex("tcp", "hasher_mutex", "hasher")

declare_rwmutex("tcp", "protocol_mutex", "protocol")

declare_mutex("tcp", "snd_queue_mutex", "sndQueue")

declare_mutex("tcp", "rcv_queue_mutex", "rcvQueue")

declare_mutex("tcp", "rcv_read_mutex", "rcvRead")

declare_mutex("tcp", "accept_mutex", "accept")

declare_mutex("tcp", "last_error_mutex", "lastError")

declare_mutex("tcp", "segment_queue_mutex", "segmentQueue")

declare_mutex("tcp", "ep_queue_mutex", "epQueue")

declare_mutex("tcp", "forwarder_mutex", "forwarder")

declare_mutex("tcp", "forwarder_request_mutex", "forwarderRequest")

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
        "accept_mutex.go",
        "connect.go",
        "connect_unsafe.go",
        "cubic.go",
        "dispatcher.go",
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
        "rcv_read_mutex.go",
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
        "tcp_endpoint_list.go",
        "tcp_segment_list.go",
        "tcp_segment_refs.go",
        "timer.go",
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
        "//pkg/sync/locking",
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

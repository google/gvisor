load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//tools/go_stateify:defs.bzl", "go_library")

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

go_library(
    name = "tcp",
    srcs = [
        "accept.go",
        "connect.go",
        "cubic.go",
        "cubic_state.go",
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
    importpath = "gvisor.dev/gvisor/pkg/tcpip/transport/tcp",
    imports = ["gvisor.dev/gvisor/pkg/tcpip/buffer"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/rand",
        "//pkg/sleep",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/iptables",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/stack",
        "//pkg/tcpip/transport/raw",
        "//pkg/tmutex",
        "//pkg/waiter",
        "@com_github_google_btree//:go_default_library",
    ],
)

go_test(
    name = "tcp_test",
    size = "medium",
    srcs = [
        "dual_stack_test.go",
        "sack_scoreboard_test.go",
        "tcp_noracedetector_test.go",
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

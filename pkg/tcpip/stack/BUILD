load("//tools:defs.bzl", "go_library", "go_test", "most_shards")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(licenses = ["notice"])

go_template_instance(
    name = "neighbor_entry_list",
    out = "neighbor_entry_list.go",
    package = "stack",
    prefix = "neighborEntry",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*neighborEntry",
        "Linker": "*neighborEntry",
    },
)

go_template_instance(
    name = "packet_buffer_list",
    out = "packet_buffer_list.go",
    package = "stack",
    prefix = "PacketBuffer",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*PacketBuffer",
        "Linker": "*PacketBuffer",
    },
)

go_template_instance(
    name = "tuple_list",
    out = "tuple_list.go",
    package = "stack",
    prefix = "tuple",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*tuple",
        "Linker": "*tuple",
    },
)

go_template_instance(
    name = "packet_buffer_refs",
    out = "packet_buffer_refs.go",
    package = "stack",
    prefix = "packetBuffer",
    template = "//pkg/refsvfs2:refs_template",
    types = {
        "T": "PacketBuffer",
    },
)

go_library(
    name = "stack",
    srcs = [
        "addressable_endpoint_state.go",
        "conntrack.go",
        "headertype_string.go",
        "hook_string.go",
        "icmp_rate_limit.go",
        "iptables.go",
        "iptables_targets.go",
        "iptables_types.go",
        "neighbor_cache.go",
        "neighbor_entry.go",
        "neighbor_entry_list.go",
        "neighborstate_string.go",
        "nic.go",
        "nic_stats.go",
        "nud.go",
        "packet_buffer.go",
        "packet_buffer_list.go",
        "packet_buffer_refs.go",
        "packet_buffer_unsafe.go",
        "pending_packets.go",
        "rand.go",
        "registration.go",
        "route.go",
        "stack.go",
        "stack_global_state.go",
        "stack_options.go",
        "tcp.go",
        "transport_demuxer.go",
        "tuple_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/buffer",
        "//pkg/ilist",
        "//pkg/log",
        "//pkg/rand",
        "//pkg/refsvfs2",
        "//pkg/sleep",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/hash/jenkins",
        "//pkg/tcpip/header",
        "//pkg/tcpip/internal/tcp",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/transport/tcpconntrack",
        "//pkg/waiter",
        "@org_golang_x_time//rate:go_default_library",
    ],
)

go_test(
    name = "stack_x_test",
    size = "small",
    srcs = [
        "addressable_endpoint_state_test.go",
        "ndp_test.go",
        "nud_test.go",
        "stack_test.go",
        "transport_demuxer_test.go",
        "transport_test.go",
    ],
    shard_count = most_shards,
    deps = [
        ":stack",
        "//pkg/rand",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

go_test(
    name = "stack_test",
    size = "small",
    srcs = [
        "conntrack_test.go",
        "forwarding_test.go",
        "iptables_test.go",
        "neighbor_cache_test.go",
        "neighbor_entry_test.go",
        "nic_test.go",
        "packet_buffer_test.go",
    ],
    library = ":stack",
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/tcpconntrack",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_library", "go_test", "most_shards")
load("//tools/go_generics:defs.bzl", "go_template_instance")
load("//pkg/sync/locking:locking.bzl", "declare_mutex", "declare_rwmutex")

package(licenses = ["notice"])

declare_rwmutex(
    name = "addressable_endpoint_state_mutex",
    out = "addressable_endpoint_state_mutex.go",
    package = "stack",
    prefix = "addressableEndpointState",
)

declare_rwmutex(
    name = "address_state_mutex",
    out = "address_state_mutex.go",
    package = "stack",
    prefix = "addressState",
)

declare_rwmutex(
    name = "route_mutex",
    out = "route_mutex.go",
    package = "stack",
    prefix = "route",
)

declare_rwmutex(
    name = "route_stack_mutex",
    out = "route_stack_mutex.go",
    package = "stack",
    prefix = "routeStack",
)

declare_rwmutex(
    name = "stack_mutex",
    out = "stack_mutex.go",
    package = "stack",
    prefix = "stack",
)

declare_rwmutex(
    name = "nic_mutex",
    out = "nic_mutex.go",
    package = "stack",
    prefix = "nic",
)

declare_rwmutex(
    name = "packet_eps_mutex",
    out = "packet_eps_mutex.go",
    package = "stack",
    prefix = "packetEPs",
)

declare_rwmutex(
    name = "packet_endpoint_list_mutex",
    out = "packet_endpoint_list_mutex.go",
    package = "stack",
    prefix = "packetEndpointList",
)

declare_rwmutex(
    name = "transport_endpoints_mutex",
    out = "transport_endpoints_mutex.go",
    package = "stack",
    prefix = "transportEndpoints",
)

declare_rwmutex(
    name = "endpoints_by_nic_mutex",
    out = "endpoints_by_nic_mutex.go",
    package = "stack",
    prefix = "endpointsByNIC",
)

declare_rwmutex(
    name = "multi_port_endpoint_mutex",
    out = "multi_port_endpoint_mutex.go",
    package = "stack",
    prefix = "multiPortEndpoint",
)

declare_rwmutex(
    name = "neighbor_entry_mutex",
    out = "neighbor_entry_mutex.go",
    package = "stack",
    prefix = "neighborEntry",
)

declare_rwmutex(
    name = "neighbor_cache_mutex",
    out = "neighbor_cache_mutex.go",
    package = "stack",
    prefix = "neighborCache",
)

declare_rwmutex(
    name = "conn_mutex",
    out = "conn_mutex.go",
    package = "stack",
    prefix = "conn",
)

declare_rwmutex(
    name = "state_conn_mutex",
    out = "state_conn_mutex.go",
    package = "stack",
    prefix = "stateConn",
)

declare_rwmutex(
    name = "bucket_mutex",
    out = "bucket_mutex.go",
    package = "stack",
    prefix = "bucket",
)

declare_rwmutex(
    name = "conn_track_mutex",
    out = "conn_track_mutex.go",
    package = "stack",
    prefix = "connTrack",
)

declare_rwmutex(
    name = "iptables_mutex",
    out = "iptables_mutex.go",
    package = "stack",
    prefix = "ipTables",
)

declare_mutex(
    name = "cleanup_endpoints_mutex",
    out = "cleanup_endpoints_mutex.go",
    package = "stack",
    prefix = "cleanupEndpoints",
)

declare_mutex(
    name = "packets_pending_link_resolution_mutex",
    out = "packets_pending_link_resolution_mutex.go",
    package = "stack",
    prefix = "packetsPendingLinkResolution",
)

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
    template = "//pkg/refs:refs_template",
    types = {
        "T": "packetBuffer",
    },
)

go_template_instance(
    name = "gro_packet_list",
    out = "gro_packet_list.go",
    package = "stack",
    prefix = "groPacket",
    template = "//pkg/ilist:generic_list",
    types = {
        "Element": "*groPacket",
        "Linker": "*groPacket",
    },
)

go_template_instance(
    name = "address_state_refs",
    out = "address_state_refs.go",
    package = "stack",
    prefix = "addressState",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "addressState",
    },
)

go_library(
    name = "stack",
    srcs = [
        "address_state_mutex.go",
        "address_state_refs.go",
        "addressable_endpoint_state.go",
        "addressable_endpoint_state_mutex.go",
        "bucket_mutex.go",
        "cleanup_endpoints_mutex.go",
        "conn_mutex.go",
        "conn_track_mutex.go",
        "conntrack.go",
        "endpoints_by_nic_mutex.go",
        "gro.go",
        "gro_packet_list.go",
        "headertype_string.go",
        "hook_string.go",
        "icmp_rate_limit.go",
        "iptables.go",
        "iptables_mutex.go",
        "iptables_targets.go",
        "iptables_types.go",
        "multi_port_endpoint_mutex.go",
        "neighbor_cache.go",
        "neighbor_cache_mutex.go",
        "neighbor_entry.go",
        "neighbor_entry_list.go",
        "neighbor_entry_mutex.go",
        "neighborstate_string.go",
        "nic.go",
        "nic_mutex.go",
        "nic_stats.go",
        "nud.go",
        "packet_buffer.go",
        "packet_buffer_list.go",
        "packet_buffer_refs.go",
        "packet_buffer_unsafe.go",
        "packet_endpoint_list_mutex.go",
        "packet_eps_mutex.go",
        "packets_pending_link_resolution_mutex.go",
        "pending_packets.go",
        "rand.go",
        "registration.go",
        "route.go",
        "route_mutex.go",
        "route_stack_mutex.go",
        "stack.go",
        "stack_global_state.go",
        "stack_mutex.go",
        "stack_options.go",
        "state_conn_mutex.go",
        "tcp.go",
        "transport_demuxer.go",
        "transport_endpoints_mutex.go",
        "tuple_list.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/ilist",
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
        "//pkg/bufferv2",
        "//pkg/rand",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/checker",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/link/loopback",
        "//pkg/tcpip/network/arp",
        "//pkg/tcpip/network/ipv4",
        "//pkg/tcpip/network/ipv6",
        "//pkg/tcpip/ports",
        "//pkg/tcpip/prependable",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/icmp",
        "//pkg/tcpip/transport/udp",
        "//pkg/waiter",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

go_test(
    name = "stack_test",
    size = "small",
    srcs = [
        "conntrack_test.go",
        "forwarding_test.go",
        "gro_test.go",
        "iptables_test.go",
        "neighbor_cache_test.go",
        "neighbor_entry_test.go",
        "nic_test.go",
        "packet_buffer_test.go",
    ],
    library = ":stack",
    deps = [
        "//pkg/atomicbitops",
        "//pkg/bufferv2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/tcpip/testutil",
        "//pkg/tcpip/transport/tcpconntrack",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

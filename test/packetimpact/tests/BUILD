load("//test/packetimpact/runner:defs.bzl", "packetimpact_go_test")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

packetimpact_go_test(
    name = "fin_wait2_timeout",
    srcs = ["fin_wait2_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "ipv4_id_uniqueness",
    srcs = ["ipv4_id_uniqueness_test.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_discard_mcast_source_addr",
    srcs = ["udp_discard_mcast_source_addr_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_recv_mcast_bcast",
    srcs = ["udp_recv_mcast_bcast_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_any_addr_recv_unicast",
    srcs = ["udp_any_addr_recv_unicast_test.go"],
    deps = [
        "//pkg/tcpip",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_icmp_error_propagation",
    srcs = ["udp_icmp_error_propagation_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_reordering",
    srcs = ["tcp_reordering_test.go"],
    # TODO(b/139368047): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_window_shrink",
    srcs = ["tcp_window_shrink_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe",
    srcs = ["tcp_zero_window_probe_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe_retransmit",
    srcs = ["tcp_zero_window_probe_retransmit_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_zero_window_probe_usertimeout",
    srcs = ["tcp_zero_window_probe_usertimeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_retransmits",
    srcs = ["tcp_retransmits_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_outside_the_window",
    srcs = ["tcp_outside_the_window_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_noaccept_close_rst",
    srcs = ["tcp_noaccept_close_rst_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_send_window_sizes_piggyback",
    srcs = ["tcp_send_window_sizes_piggyback_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_unacc_seq_ack",
    srcs = ["tcp_unacc_seq_ack_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_paws_mechanism",
    srcs = ["tcp_paws_mechanism_test.go"],
    # TODO(b/156682000): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_user_timeout",
    srcs = ["tcp_user_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_queue_receive_in_syn_sent",
    srcs = ["tcp_queue_receive_in_syn_sent_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_synsent_reset",
    srcs = ["tcp_synsent_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_synrcvd_reset",
    srcs = ["tcp_synrcvd_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_network_unreachable",
    srcs = ["tcp_network_unreachable_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_cork_mss",
    srcs = ["tcp_cork_mss_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_handshake_window_size",
    srcs = ["tcp_handshake_window_size_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_timewait_reset",
    srcs = ["tcp_timewait_reset_test.go"],
    # TODO(b/168523247): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "icmpv6_param_problem",
    srcs = ["icmpv6_param_problem_test.go"],
    # TODO(b/153485026): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "ipv6_unknown_options_action",
    srcs = ["ipv6_unknown_options_action_test.go"],
    # TODO(b/159928940): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "ipv6_fragment_reassembly",
    srcs = ["ipv6_fragment_reassembly_test.go"],
    # TODO(b/160919104): Fix netstack then remove the line below.
    expect_netstack_failure = True,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_send_recv_dgram",
    srcs = ["udp_send_recv_dgram_test.go"],
    deps = [
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

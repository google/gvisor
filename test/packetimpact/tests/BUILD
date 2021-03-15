load("//test/packetimpact/runner:defs.bzl", "ALL_TESTS", "packetimpact_go_test", "packetimpact_testbench", "validate_all_tests")

package(
    default_visibility = ["//test/packetimpact:__subpackages__"],
    licenses = ["notice"],
)

packetimpact_testbench(
    name = "fin_wait2_timeout",
    srcs = ["fin_wait2_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "ipv4_id_uniqueness",
    srcs = ["ipv4_id_uniqueness_test.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "udp_discard_mcast_source_addr",
    srcs = ["udp_discard_mcast_source_addr_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "udp_any_addr_recv_unicast",
    srcs = ["udp_any_addr_recv_unicast_test.go"],
    deps = [
        "//pkg/tcpip",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "udp_icmp_error_propagation",
    srcs = ["udp_icmp_error_propagation_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_window_shrink",
    srcs = ["tcp_window_shrink_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_zero_window_probe",
    srcs = ["tcp_zero_window_probe_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_zero_window_probe_retransmit",
    srcs = ["tcp_zero_window_probe_retransmit_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_zero_window_probe_usertimeout",
    srcs = ["tcp_zero_window_probe_usertimeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_retransmits",
    srcs = ["tcp_retransmits_test.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/tcpip/header",
        "//pkg/usermem",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_outside_the_window",
    srcs = ["tcp_outside_the_window_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_outside_the_window_closing",
    srcs = ["tcp_outside_the_window_closing_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_noaccept_close_rst",
    srcs = ["tcp_noaccept_close_rst_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_send_window_sizes_piggyback",
    srcs = ["tcp_send_window_sizes_piggyback_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_unacc_seq_ack",
    srcs = ["tcp_unacc_seq_ack_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_unacc_seq_ack_closing",
    srcs = ["tcp_unacc_seq_ack_closing_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_paws_mechanism",
    srcs = ["tcp_paws_mechanism_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_user_timeout",
    srcs = ["tcp_user_timeout_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_queue_send_recv_in_syn_sent",
    srcs = ["tcp_queue_send_recv_in_syn_sent_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_synsent_reset",
    srcs = ["tcp_synsent_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_synrcvd_reset",
    srcs = ["tcp_synrcvd_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_network_unreachable",
    srcs = ["tcp_network_unreachable_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_cork_mss",
    srcs = ["tcp_cork_mss_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_handshake_window_size",
    srcs = ["tcp_handshake_window_size_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_timewait_reset",
    srcs = ["tcp_timewait_reset_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "icmpv6_param_problem",
    srcs = ["icmpv6_param_problem_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "ipv6_unknown_options_action",
    srcs = ["ipv6_unknown_options_action_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "ipv4_fragment_reassembly",
    srcs = ["ipv4_fragment_reassembly_test.go"],
    deps = [
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "ipv6_fragment_reassembly",
    srcs = ["ipv6_fragment_reassembly_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "ipv6_fragment_icmp_error",
    srcs = ["ipv6_fragment_icmp_error_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
        "//pkg/tcpip/network/ipv6",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "udp_send_recv_dgram",
    srcs = ["udp_send_recv_dgram_test.go"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_linger",
    srcs = ["tcp_linger_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_rcv_buf_space",
    srcs = ["tcp_rcv_buf_space_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_zero_receive_window",
    srcs = ["tcp_zero_receive_window_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_rack",
    srcs = ["tcp_rack_test.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "//pkg/usermem",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_info",
    srcs = ["tcp_info_test.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/binary",
        "//pkg/tcpip/header",
        "//pkg/usermem",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_testbench(
    name = "tcp_fin_retransmission",
    srcs = ["tcp_fin_retransmission_test.go"],
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

validate_all_tests()

[packetimpact_go_test(
    name = t.name,
    expect_netstack_failure = hasattr(t, "expect_netstack_failure"),
    num_duts = t.num_duts if hasattr(t, "num_duts") else 1,
) for t in ALL_TESTS]

test_suite(
    name = "all_tests",
    tags = [
        "manual",
        "packetimpact",
    ],
    tests = existing_rules(),
)

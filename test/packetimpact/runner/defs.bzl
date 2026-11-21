"""Defines rules for packetimpact test targets."""

load("@bazel_skylib//rules:native_binary.bzl", "native_test")
load("//tools:defs.bzl", "go_test")

PACKETIMPACT_TAGS = [
    "manual",
    "notap",
    "packetimpact",
]

def _packetimpact_test(
        name,
        testbench_binary,
        dut_binary,
        variant,
        expect_failure,
        num_duts = 1,
        args = [],
        **kwargs):
    # The DUT needs its runfiles in the new user namespace, including its
    # POSIX server and, for netstack, runsc and its sidecars.
    native_test(
        name = name,
        src = "//test/packetimpact/runner:main",
        out = name + "-bench",
        args = [
            "--variant=" + variant,
            "--dut_binary=$(rootpath %s)" % dut_binary,
            "--testbench_binary=$(rootpath %s)" % testbench_binary,
            "--num_duts=%d" % num_duts,
        ] + (["--expect_failure"] if expect_failure else []) + args,
        data = [dut_binary, testbench_binary],
        tags = PACKETIMPACT_TAGS,
        **kwargs
    )

def packetimpact_native_test(
        name,
        testbench_binary,
        expect_failure = False,
        **kwargs):
    """Add a native packetimpact test.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    _packetimpact_test(
        name = name + "_native_test",
        testbench_binary = testbench_binary,
        dut_binary = "//test/packetimpact/dut/native",
        variant = "native",
        expect_failure = expect_failure,
        **kwargs
    )

def packetimpact_netstack_test(
        name,
        testbench_binary,
        expect_failure = False,
        **kwargs):
    """Add a packetimpact test on netstack.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    _packetimpact_test(
        name = name + "_netstack_test",
        testbench_binary = testbench_binary,
        dut_binary = "//test/packetimpact/dut/runsc",
        variant = "gvisor",
        expect_failure = expect_failure,
        **kwargs
    )

def packetimpact_go_test(name, expect_native_failure = False, expect_netstack_failure = False, num_duts = 1, **kwargs):
    """Add packetimpact tests written in go.

    Args:
        name: name of the test
        expect_native_failure: the test must fail natively
        expect_netstack_failure: the test must fail for Netstack
        num_duts: how many DUTs are needed for the test
        **kwargs: all the other args, forwarded to packetimpact_native_test and packetimpact_netstack_test
    """
    testbench_binary = name + "_test"
    packetimpact_native_test(
        name = name,
        expect_failure = expect_native_failure,
        num_duts = num_duts,
        testbench_binary = testbench_binary,
        **kwargs
    )
    packetimpact_netstack_test(
        name = name,
        expect_failure = expect_netstack_failure,
        num_duts = num_duts,
        testbench_binary = testbench_binary,
        **kwargs
    )

def packetimpact_testbench(name, size = "small", pure = True, **kwargs):
    """Build packetimpact testbench written in go.

    Args:
        name: name of the test
        size: size of the test
        pure: make a static go binary
        **kwargs: all the other args, forwarded to go_test
    """
    go_test(
        name = name + "_test",
        size = size,
        pure = pure,
        nogo = False,  # FIXME(gvisor.dev/issue/3374): Not working with all build systems.
        tags = [
            "manual",
            "notap",
        ],
        **kwargs
    )

PacketimpactTestInfo = provider(
    doc = "Provide information for packetimpact tests",
    fields = [
        "name",
        "timeout",
        "expect_netstack_failure",
        "num_duts",
    ],
)

ALL_TESTS = [
    PacketimpactTestInfo(
        name = "fin_wait2_timeout",
    ),
    PacketimpactTestInfo(
        name = "ipv4_id_uniqueness",
    ),
    PacketimpactTestInfo(
        name = "udp_discard_mcast_source_addr",
    ),
    PacketimpactTestInfo(
        name = "udp_any_addr_recv_unicast",
    ),
    PacketimpactTestInfo(
        name = "udp_icmp_error_propagation",
    ),
    PacketimpactTestInfo(
        name = "tcp_window_shrink",
    ),
    PacketimpactTestInfo(
        name = "tcp_zero_window_probe",
    ),
    PacketimpactTestInfo(
        name = "tcp_zero_window_probe_retransmit",
    ),
    PacketimpactTestInfo(
        name = "tcp_zero_window_probe_usertimeout",
    ),
    PacketimpactTestInfo(
        name = "tcp_retransmits",
    ),
    PacketimpactTestInfo(
        name = "tcp_outside_the_window",
    ),
    PacketimpactTestInfo(
        name = "tcp_noaccept_close_rst",
    ),
    PacketimpactTestInfo(
        name = "tcp_send_window_sizes_piggyback",
    ),
    PacketimpactTestInfo(
        name = "tcp_unacc_seq_ack",
    ),
    PacketimpactTestInfo(
        name = "tcp_paws_mechanism",
        # TODO(b/156682000): Fix netstack then remove the line below.
        expect_netstack_failure = True,
    ),
    PacketimpactTestInfo(
        name = "tcp_user_timeout",
    ),
    PacketimpactTestInfo(
        name = "tcp_zero_receive_window",
    ),
    PacketimpactTestInfo(
        name = "tcp_queue_send_recv_in_syn_sent",
    ),
    PacketimpactTestInfo(
        name = "tcp_synsent_reset",
    ),
    PacketimpactTestInfo(
        name = "tcp_synrcvd_reset",
    ),
    PacketimpactTestInfo(
        name = "tcp_network_unreachable",
    ),
    PacketimpactTestInfo(
        name = "tcp_cork_mss",
    ),
    PacketimpactTestInfo(
        name = "tcp_handshake_window_size",
    ),
    PacketimpactTestInfo(
        name = "tcp_timewait_reset",
        # TODO(b/168523247): Fix netstack then remove the line below.
        expect_netstack_failure = True,
    ),
    PacketimpactTestInfo(
        name = "tcp_listen_backlog",
    ),
    PacketimpactTestInfo(
        name = "tcp_syncookie",
    ),
    PacketimpactTestInfo(
        name = "tcp_connect_icmp_error",
    ),
    PacketimpactTestInfo(
        name = "icmpv6_param_problem",
    ),
    PacketimpactTestInfo(
        name = "ipv6_unknown_options_action",
    ),
    PacketimpactTestInfo(
        name = "ipv4_fragment_reassembly",
    ),
    PacketimpactTestInfo(
        name = "ipv6_fragment_reassembly",
    ),
    PacketimpactTestInfo(
        name = "ipv6_fragment_icmp_error",
        num_duts = 3,
    ),
    PacketimpactTestInfo(
        name = "tcp_linger",
    ),
    PacketimpactTestInfo(
        name = "tcp_rcv_buf_space",
    ),
    PacketimpactTestInfo(
        name = "tcp_rack",
    ),
    PacketimpactTestInfo(
        name = "tcp_info",
    ),
    PacketimpactTestInfo(
        name = "tcp_fin_retransmission",
    ),
    PacketimpactTestInfo(
        name = "icmpv4_socket_send_recv",
        timeout = "long",
    ),
    PacketimpactTestInfo(
        name = "icmpv6_socket_send_recv",
        timeout = "long",
    ),
    PacketimpactTestInfo(
        name = "udp_socket_send_recv",
        timeout = "long",
    ),
    PacketimpactTestInfo(
        name = "tcp_acceptable_ack_syn_rcvd",
    ),
]

def validate_all_tests():
    """
    Make sure that ALL_TESTS list is in sync with the rules in BUILD.

    This function is order-dependent, it is intended to be used after
    all packetimpact_testbench rules and before using ALL_TESTS list
    at the end of BUILD.
    """
    all_tests_dict = {}  # there is no set, using dict to approximate.
    for test in ALL_TESTS:
        rule_name = test.name + "_test"
        all_tests_dict[rule_name] = True
        if not native.existing_rule(rule_name):
            fail("%s does not have a packetimpact_testbench rule in BUILD" % test.name)
    for name in native.existing_rules():
        if name.endswith("_test") and name not in all_tests_dict:
            fail("%s is not declared in ALL_TESTS list in defs.bzl" % name[:-5])

"""Defines rules for packetimpact test targets."""

load("//tools:defs.bzl", "go_test")

def _packetimpact_test_impl(ctx):
    test_runner = ctx.executable.test_runner
    bench = ctx.actions.declare_file("%s-bench" % ctx.label.name)
    dut_binary_flag = [] if ctx.attr.dut_binary == None else [
        "--dut_binary",
        ctx.file.dut_binary.short_path,
    ]
    bench_content = "\n".join([
        "#!/bin/bash",
        # This test will run part in a distinct user namespace. This can cause
        # permission problems, because all runfiles may not be owned by the
        # current user, and no other users will be mapped in that namespace.
        # Make sure that everything is readable here.
        "find . -type f -or -type d -exec chmod a+rx {} \\;",
        "%s %s --testbench_binary %s --num_duts %d $@\n" % (
            test_runner.short_path,
            " ".join(ctx.attr.flags + dut_binary_flag),
            ctx.files.testbench_binary[0].short_path,
            ctx.attr.num_duts,
        ),
    ])
    ctx.actions.write(bench, bench_content, is_executable = True)

    transitive_files = []
    if hasattr(ctx.attr.test_runner, "data_runfiles"):
        transitive_files.append(ctx.attr.test_runner.data_runfiles.files)
    if hasattr(ctx.attr.dut_binary, "data_runfiles"):
        transitive_files.append(ctx.attr.dut_binary.data_runfiles.files)
    files = [test_runner] + ctx.files.testbench_binary + ctx.files._posix_server + ctx.files.dut_binary
    runfiles = ctx.runfiles(
        files = files,
        transitive_files = depset(transitive = transitive_files),
        collect_default = True,
        collect_data = True,
    )
    return [DefaultInfo(executable = bench, runfiles = runfiles)]

_packetimpact_test = rule(
    attrs = {
        "test_runner": attr.label(
            executable = True,
            cfg = "target",
            default = ":packetimpact_test",
        ),
        "_posix_server": attr.label(
            cfg = "target",
            default = "//test/packetimpact/dut:posix_server",
        ),
        "testbench_binary": attr.label(
            cfg = "target",
            mandatory = True,
        ),
        "flags": attr.string_list(
            mandatory = False,
            default = [],
        ),
        "num_duts": attr.int(
            mandatory = False,
            default = 1,
        ),
        "dut_binary": attr.label(
            executable = True,
            cfg = "target",
            allow_single_file = True,
        ),
    },
    test = True,
    implementation = _packetimpact_test_impl,
)

PACKETIMPACT_TAGS = [
    "local",
    "manual",
    "packetimpact",
]

def packetimpact_native_test(
        name,
        testbench_binary,
        expect_failure = False,
        legacy_runner = False,
        **kwargs):
    """Add a native packetimpact test.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        legacy_runner: use the legacy docker runner
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    expect_failure_flag = ["--expect_failure"] if expect_failure else []
    if legacy_runner:
        _packetimpact_test(
            name = name + "_native_test",
            testbench_binary = testbench_binary,
            flags = ["--native"] + expect_failure_flag,
            tags = PACKETIMPACT_TAGS,
            **kwargs
        )
    else:
        _packetimpact_test(
            test_runner = "//test/packetimpact/runner:main",
            name = name + "_native_test",
            testbench_binary = testbench_binary,
            flags = expect_failure_flag + ["--variant", "native"],
            dut_binary = "//test/packetimpact/dut/native",
            tags = PACKETIMPACT_TAGS,
            **kwargs
        )

def packetimpact_netstack_test(
        name,
        testbench_binary,
        expect_failure = False,
        legacy_runner = False,
        **kwargs):
    """Add a packetimpact test on netstack.

    Args:
        name: name of the test
        testbench_binary: the testbench binary
        expect_failure: the test must fail
        legacy_runner: use the legacy docker runner
        **kwargs: all the other args, forwarded to _packetimpact_test
    """
    expect_failure_flag = []
    if expect_failure:
        expect_failure_flag = ["--expect_failure"]
    if legacy_runner:
        _packetimpact_test(
            name = name + "_netstack_test",
            testbench_binary = testbench_binary,
            # Note that a distinct runtime must be provided in the form
            # --test_arg=--runtime=other when invoking bazel.
            flags = expect_failure_flag,
            tags = PACKETIMPACT_TAGS,
            **kwargs
        )
    else:
        _packetimpact_test(
            test_runner = "//test/packetimpact/runner:main",
            name = name + "_netstack_test",
            testbench_binary = testbench_binary,
            flags = expect_failure_flag + ["--variant", "gvisor"],
            dut_binary = "//test/packetimpact/dut/runsc",
            tags = PACKETIMPACT_TAGS,
            **kwargs
        )

def packetimpact_go_test(name, expect_native_failure = False, expect_netstack_failure = False, num_duts = 1, legacy_runner = False, **kwargs):
    """Add packetimpact tests written in go.

    Args:
        name: name of the test
        expect_native_failure: the test must fail natively
        expect_netstack_failure: the test must fail for Netstack
        num_duts: how many DUTs are needed for the test
        legacy_runner: use the legacy docker runner
        **kwargs: all the other args, forwarded to packetimpact_native_test and packetimpact_netstack_test
    """
    testbench_binary = name + "_test"
    packetimpact_native_test(
        name = name,
        expect_failure = expect_native_failure,
        num_duts = num_duts,
        testbench_binary = testbench_binary,
        legacy_runner = legacy_runner,
        **kwargs
    )
    packetimpact_netstack_test(
        name = name,
        expect_failure = expect_netstack_failure,
        num_duts = num_duts,
        testbench_binary = testbench_binary,
        legacy_runner = legacy_runner,
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
            "local",
            "manual",
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
        "legacy_runner",
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
        expect_netstack_failure = True,
    ),
    PacketimpactTestInfo(
        name = "tcp_info",
    ),
    PacketimpactTestInfo(
        name = "tcp_fin_retransmission",
    ),
    PacketimpactTestInfo(
        name = "generic_dgram_socket_send_recv",
        timeout = "long",
        # This test has assumed the presense of the default interface and the
        # default route installed by docker, using the docker until the test
        # is migrated.
        legacy_runner = True,
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

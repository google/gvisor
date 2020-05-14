load("defs.bzl", "packetimpact_go_test")

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
    name = "udp_recv_multicast",
    srcs = ["udp_recv_multicast_test.go"],
    # TODO(b/152813495): Fix netstack then remove the line below.
    netstack = False,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "udp_icmp_error_propagation",
    srcs = ["udp_icmp_error_propagation_test.go"],
    # TODO(b/153926291): Fix netstack then remove the line below.
    netstack = False,
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
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
    name = "tcp_should_piggyback",
    srcs = ["tcp_should_piggyback_test.go"],
    # TODO(b/153680566): Fix netstack then remove the line below.
    netstack = False,
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

packetimpact_go_test(
    name = "tcp_close_wait_ack",
    srcs = ["tcp_close_wait_ack_test.go"],
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
    name = "icmpv6_param_problem",
    srcs = ["icmpv6_param_problem_test.go"],
    # TODO(b/153485026): Fix netstack then remove the line below.
    netstack = False,
    deps = [
        "//pkg/tcpip",
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
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

sh_binary(
    name = "test_runner",
    srcs = ["test_runner.sh"],
)

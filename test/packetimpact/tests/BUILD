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
    name = "tcp_window_shrink",
    srcs = ["tcp_window_shrink_test.go"],
    # TODO(b/153202472): Fix netstack then remove the line below.
    netstack = False,
    deps = [
        "//pkg/tcpip/header",
        "//test/packetimpact/testbench",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

sh_binary(
    name = "test_runner",
    srcs = ["test_runner.sh"],
)

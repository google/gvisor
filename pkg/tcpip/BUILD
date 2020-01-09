load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "tcpip",
    srcs = [
        "packet_buffer.go",
        "packet_buffer_state.go",
        "tcpip.go",
        "time_unsafe.go",
        "timer.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/iptables",
        "//pkg/waiter",
    ],
)

go_test(
    name = "tcpip_test",
    size = "small",
    srcs = ["tcpip_test.go"],
    embed = [":tcpip"],
)

go_test(
    name = "timer_test",
    size = "small",
    srcs = ["timer_test.go"],
    deps = [":tcpip"],
)

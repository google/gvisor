load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "tcpip",
    srcs = [
        "tcpip.go",
        "time_unsafe.go",
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

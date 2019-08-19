load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "tcpconntrack",
    srcs = ["tcp_conntrack.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/transport/tcpconntrack",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
    ],
)

go_test(
    name = "tcpconntrack_test",
    size = "small",
    srcs = ["tcp_conntrack_test.go"],
    deps = [
        ":tcpconntrack",
        "//pkg/tcpip/header",
    ],
)

package(licenses = ["notice"])  # Apache 2.0

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "tcpconntrack",
    srcs = ["tcp_conntrack.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcpconntrack",
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

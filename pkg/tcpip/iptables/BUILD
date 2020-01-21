load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "iptables",
    srcs = [
        "iptables.go",
        "targets.go",
        "tcp_matcher.go",
        "types.go",
        "udp_matcher.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/iptables",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)

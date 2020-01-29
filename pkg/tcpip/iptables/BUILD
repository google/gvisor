load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "iptables",
    srcs = [
        "iptables.go",
        "targets.go",
        "types.go",
        "udp_matcher.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/log",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
    ],
)

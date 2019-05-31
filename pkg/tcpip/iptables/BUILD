package(licenses = ["notice"])

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

go_library(
    name = "iptables",
    srcs = [
        "iptables.go",
        "targets.go",
        "types.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/iptables",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/state",
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/header",
    ],
)

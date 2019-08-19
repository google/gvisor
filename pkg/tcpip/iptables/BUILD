package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "iptables",
    srcs = [
        "iptables.go",
        "targets.go",
        "types.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/iptables",
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip/buffer"],
)

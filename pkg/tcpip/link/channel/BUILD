package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "channel",
    srcs = ["channel.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/link/channel",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/buffer",
        "//pkg/tcpip/stack",
    ],
)

package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "ports",
    srcs = ["ports.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tcpip/ports",
    visibility = ["//:sandbox"],
    deps = ["//pkg/tcpip"],
)

go_test(
    name = "ports_test",
    srcs = ["ports_test.go"],
    embed = [":ports"],
    deps = [
        "//pkg/tcpip",
    ],
)

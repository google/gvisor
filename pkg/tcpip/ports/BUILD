load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "ports",
    srcs = ["ports.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/ports",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
    ],
)

go_test(
    name = "ports_test",
    srcs = ["ports_test.go"],
    embed = [":ports"],
    deps = [
        "//pkg/tcpip",
    ],
)

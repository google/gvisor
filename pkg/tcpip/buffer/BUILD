load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

load("//tools:defs.bzl", "go_library")

go_library(
    name = "buffer",
    srcs = [
        "prependable.go",
        "view.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/buffer",
    visibility = ["//visibility:public"],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = ["view_test.go"],
    embed = [":buffer"],
)

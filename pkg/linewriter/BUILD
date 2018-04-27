package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "linewriter",
    srcs = ["linewriter.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/linewriter",
    visibility = ["//visibility:public"],
)

go_test(
    name = "linewriter_test",
    srcs = ["linewriter_test.go"],
    embed = [":linewriter"],
)

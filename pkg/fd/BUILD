package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "fd",
    srcs = ["fd.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/fd",
    visibility = ["//visibility:public"],
)

go_test(
    name = "fd_test",
    size = "small",
    srcs = ["fd_test.go"],
    embed = [":fd"],
)

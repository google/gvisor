package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "binary",
    srcs = ["binary.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/binary",
    visibility = ["//:sandbox"],
)

go_test(
    name = "binary_test",
    size = "small",
    srcs = ["binary_test.go"],
    embed = [":binary"],
)

package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "compressio",
    srcs = ["compressio.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/compressio",
    visibility = ["//:sandbox"],
    deps = ["//pkg/binary"],
)

go_test(
    name = "compressio_test",
    size = "medium",
    srcs = ["compressio_test.go"],
    embed = [":compressio"],
)

package(licenses = ["notice"])  # BSD

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "tmutex",
    srcs = ["tmutex.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/tmutex",
    visibility = ["//:sandbox"],
)

go_test(
    name = "tmutex_test",
    size = "medium",
    srcs = ["tmutex_test.go"],
    embed = [":tmutex"],
)

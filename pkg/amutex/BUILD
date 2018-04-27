package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "amutex",
    srcs = ["amutex.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/amutex",
    visibility = ["//:sandbox"],
)

go_test(
    name = "amutex_test",
    size = "small",
    srcs = ["amutex_test.go"],
    embed = [":amutex"],
)

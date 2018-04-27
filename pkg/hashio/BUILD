package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "hashio",
    srcs = [
        "hashio.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/hashio",
    visibility = ["//:sandbox"],
)

go_test(
    name = "hashio_test",
    size = "small",
    srcs = ["hashio_test.go"],
    embed = [":hashio"],
)

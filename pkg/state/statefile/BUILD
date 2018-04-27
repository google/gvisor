package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "statefile",
    srcs = ["statefile.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/state/statefile",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/binary",
        "//pkg/compressio",
        "//pkg/hashio",
    ],
)

go_test(
    name = "statefile_test",
    size = "small",
    srcs = ["statefile_test.go"],
    embed = [":statefile"],
    deps = ["//pkg/hashio"],
)

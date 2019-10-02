load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "statefile",
    srcs = ["statefile.go"],
    importpath = "gvisor.dev/gvisor/pkg/state/statefile",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/binary",
        "//pkg/compressio",
    ],
)

go_test(
    name = "statefile_test",
    size = "small",
    srcs = ["statefile_test.go"],
    embed = [":statefile"],
    deps = ["//pkg/compressio"],
)

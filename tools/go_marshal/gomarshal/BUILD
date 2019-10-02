load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "gomarshal",
    srcs = [
        "generator.go",
        "generator_interfaces.go",
        "generator_tests.go",
        "util.go",
    ],
    importpath = "gvisor.dev/gvisor/tools/go_marshal/gomarshal",
    visibility = [
        "//:sandbox",
    ],
)

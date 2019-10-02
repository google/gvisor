load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "analysis",
    testonly = 1,
    srcs = ["analysis_unsafe.go"],
    importpath = "gvisor.dev/gvisor/tools/go_marshal/analysis",
    visibility = [
        "//:sandbox",
    ],
)

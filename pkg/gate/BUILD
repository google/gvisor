load("//tools/go_stateify:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "gate",
    srcs = [
        "gate.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/gate",
    visibility = ["//visibility:public"],
)

go_test(
    name = "gate_test",
    srcs = [
        "gate_test.go",
    ],
    deps = [
        ":gate",
    ],
)

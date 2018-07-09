package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "gate",
    srcs = [
        "gate.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/gate",
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

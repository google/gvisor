package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "urpc",
    srcs = ["urpc.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/urpc",
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/unet",
    ],
)

go_test(
    name = "urpc_test",
    size = "small",
    srcs = ["urpc_test.go"],
    embed = [":urpc"],
    deps = ["//pkg/unet"],
)

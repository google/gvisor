load("@io_bazel_rules_go//go:def.bzl", "go_test")
load("//tools/go_stateify:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "device",
    srcs = ["device.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/device",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/abi/linux"],
)

go_test(
    name = "device_test",
    size = "small",
    srcs = ["device_test.go"],
    embed = [":device"],
)

load("//tools/go_stateify:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])  # Apache 2.0

go_library(
    name = "device",
    srcs = ["device.go"],
    importpath = "gvisor.googlesource.com/gvisor/pkg/sentry/device",
    visibility = ["//pkg/sentry:internal"],
    deps = ["//pkg/abi/linux"],
)

go_test(
    name = "device_test",
    size = "small",
    srcs = ["device_test.go"],
    embed = [":device"],
)

load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

exports_files(["schema.json"])

go_library(
    name = "config",
    srcs = ["config.go"],
    importpath = "gvisor.dev/gvisor/tools/nogo/config",
    visibility = ["//tools/nogo:__subpackages__"],
    deps = ["//tools/nogo/check"],
)

go_test(
    name = "config_test",
    size = "small",
    srcs = ["config_test.go"],
    embed = [":config"],
    deps = ["//tools/nogo/check"],
)

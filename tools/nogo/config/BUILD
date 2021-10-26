load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

exports_files(["schema.json"])

go_library(
    name = "config",
    srcs = ["config.go"],
    visibility = ["//tools/nogo:__subpackages__"],
    deps = ["//tools/nogo/check"],
)

go_test(
    name = "config_test",
    size = "small",
    srcs = ["config_test.go"],
    library = ":config",
    deps = ["//tools/nogo/check"],
)

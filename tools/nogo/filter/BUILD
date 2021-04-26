load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "filter",
    srcs = ["main.go"],
    nogo = False,
    visibility = ["//visibility:public"],
    deps = [
        "//tools/nogo",
        "//tools/worker",
        "@in_gopkg_yaml_v2//:go_default_library",
    ],
)

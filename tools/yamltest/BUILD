load("//tools:defs.bzl", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "yamltest",
    srcs = ["main.go"],
    visibility = ["//visibility:public"],
    deps = [
        "@com_github_xeipuuv_gojsonschema//:go_default_library",
        "@in_gopkg_yaml_v2//:go_default_library",
    ],
)

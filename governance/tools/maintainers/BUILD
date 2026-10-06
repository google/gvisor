load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "maintainers_gen",
    srcs = ["maintainers_gen.go"],
    visibility = ["//governance:__pkg__"],
    deps = ["@in_gopkg_yaml_v3//:go_default_library"],
)

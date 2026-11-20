load("//tools:defs.bzl", "bzl_library", "go_binary")

package(default_applicable_licenses = ["//:license"])

go_binary(
    name = "compare",
    testonly = True,
    srcs = ["compare.go"],
    pure = True,
    visibility = ["//tools/go_generics/tests:__subpackages__"],
    deps = [
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_google_go_cmp//cmp/cmpopts:go_default_library",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
    deps = ["@bazel_skylib//rules:native_binary"],
)

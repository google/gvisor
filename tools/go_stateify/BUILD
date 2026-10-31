load("//tools:defs.bzl", "bzl_library", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "stateify",
    srcs = ["main.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//tools/constraintutil",
        "@org_golang_x_tools//imports",
    ],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)

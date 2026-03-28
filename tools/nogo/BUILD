load("//tools:defs.bzl", "bzl_library", "go_binary", "select_goarch", "select_goos")
load("//tools/nogo:defs.bzl", "nogo_stdlib", "nogo_target")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

nogo_target(
    name = "target",
    goarch = select_goarch(),
    goos = select_goos(),
    visibility = ["//visibility:public"],
)

nogo_stdlib(
    name = "stdlib",
    visibility = ["//visibility:public"],
)

go_binary(
    name = "nogo",
    srcs = ["main.go"],
    visibility = ["//visibility:public"],
    deps = ["//tools/nogo/cli"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)

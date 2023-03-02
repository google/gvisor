load("//tools:defs.bzl", "bzl_library", "go_binary")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_binary(
    name = "fieldenum",
    srcs = ["main.go"],
    visibility = ["//:sandbox"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)

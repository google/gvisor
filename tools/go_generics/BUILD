load("//tools:defs.bzl", "bzl_library", "go_binary")

package(licenses = ["notice"])

go_binary(
    name = "go_generics",
    srcs = [
        "imports.go",
        "main.go",
        "remove.go",
    ],
    visibility = ["//:sandbox"],
    deps = ["//tools/go_generics/globals"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = ["//visibility:private"],
)

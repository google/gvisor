load("//tools:defs.bzl", "bzl_library", "go_binary")
load("//tools/go_generics:defs.bzl", "go_template")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

bzl_library(
    name = "defs_bzl",
    srcs = ["defs.bzl"],
    visibility = [
        "//:sandbox",
    ],
)

go_template(
    name = "embeddedbinary_template",
    srcs = ["embeddedbinary_template.go"],
    visibility = [
        "//:sandbox",
    ],
)

go_binary(
    name = "flatecompress",
    srcs = ["flatecompress.go"],
    visibility = [
        "//:sandbox",
    ],
)

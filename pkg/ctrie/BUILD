package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template")

go_template(
    name = "generic_ctrie",
    srcs = [
        "ctrie.go",
        "ctrie_unsafe.go",
    ],
    opt_consts = [
        "bitsPerLevel",
    ],
    opt_types = [
        "Key",
        "Value",
    ],
)

go_library(
    name = "ctrie",
    srcs = [
        "ctrie.go",
        "ctrie_unsafe.go",
    ],
)

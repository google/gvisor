load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "facts",
    srcs = ["facts.go"],
    visibility = ["//tools:__subpackages__"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_default_library",
        "@org_golang_x_tools//go/types/objectpath:go_default_library",
    ],
)

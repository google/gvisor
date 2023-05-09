load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "flags",
    srcs = ["flags.go"],
    visibility = ["//tools:__subpackages__"],
    deps = ["//runsc/flag"],
)

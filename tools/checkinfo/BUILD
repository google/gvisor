load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checkinfo",
    srcs = ["checkinfo.go"],
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = ["@org_golang_x_tools//go/analysis:go_default_library"],
)

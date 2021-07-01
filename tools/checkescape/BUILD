load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checkescape",
    srcs = ["checkescape.go"],
    nogo = False,
    visibility = ["//tools/nogo:__subpackages__"],
    deps = [
        "//tools/nogo/objdump",
        "@org_golang_x_tools//go/analysis:go_default_library",
        "@org_golang_x_tools//go/analysis/passes/buildssa:go_default_library",
        "@org_golang_x_tools//go/ssa:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_tool_library")

package(licenses = ["notice"])

go_tool_library(
    name = "checkescape",
    srcs = ["checkescape.go"],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_tool_library",
        "@org_golang_x_tools//go/analysis/passes/buildssa:go_tool_library",
        "@org_golang_x_tools//go/ssa:go_tool_library",
    ],
)

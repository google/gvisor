load("//tools:defs.bzl", "go_tool_library")

package(licenses = ["notice"])

go_tool_library(
    name = "checkunsafe",
    srcs = ["check_unsafe.go"],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_x_tools//go/analysis:go_tool_library",
    ],
)

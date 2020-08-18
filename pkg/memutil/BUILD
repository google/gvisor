load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "memutil",
    srcs = ["memutil_unsafe.go"],
    visibility = ["//visibility:public"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)

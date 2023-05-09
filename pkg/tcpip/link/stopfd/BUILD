load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stopfd",
    srcs = [
        "stopfd.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_library")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_library(
    name = "devutil",
    srcs = [
        "context.go",
        "devutil.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/context",
        "//pkg/fsutil",
        "//pkg/lisafs",
        "//pkg/log",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

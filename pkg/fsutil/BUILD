load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "fsutil",
    srcs = [
        "fsutil.go",
        "fsutil_amd64_unsafe.go",
        "fsutil_arm64_unsafe.go",
        "fsutil_unsafe.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/syserr",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

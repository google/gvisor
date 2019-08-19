load("//tools:defs.bzl", "go_library")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

package(licenses = ["notice"])

go_library(
    name = "unet",
    srcs = [
        "unet.go",
        "unet_unsafe.go",
    ],
    importpath = "gvisor.dev/gvisor/pkg/unet",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/gate",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "unet_test",
    size = "small",
    srcs = [
        "unet_test.go",
    ],
    embed = [":unet"],
)

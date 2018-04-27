package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

go_library(
    name = "unet",
    srcs = [
        "unet.go",
        "unet_unsafe.go",
    ],
    importpath = "gvisor.googlesource.com/gvisor/pkg/unet",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/gate",
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

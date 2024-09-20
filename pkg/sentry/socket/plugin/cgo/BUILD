load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

config_setting(
    name = "network_plugins",
    values = {"define": "network_plugins=true"},
)

go_library(
    name = "cgo",
    srcs = [
        "nocgo_stub_unsafe.go",
        "socket_unsafe.go",
        "stack_unsafe.go",
        "util_unsafe.go",
    ],
    bazel_cdeps = [
        "@libpluginstack//:libpluginstack",
    ],
    bazel_cgo = select({
        ":network_plugins": True,
        "//conditions:default": False,
    }),
    bazel_clinkopts = [
        "-L external/libpluginstack",
    ],
    bazel_copts = [
        "-march=native",
        "-I external/libpluginstack/lib/libtle_glue",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
    ],
)

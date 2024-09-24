load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

config_setting(
    name = "network_plugins",
    values = {"define": "network_plugins=true"},
)

go_library(
    name = "cgo",
    srcs = [
        "cgo.go",
        "nocgo_stub_unsafe.go",
        "socket_unsafe.go",
        "stack_unsafe.go",
        "util_unsafe.go",
    ],
    bazel_cdeps = select({
        ":network_plugins": ["@libpluginstack//:libpluginstack"],
        "//conditions:default": [],
    }),
    bazel_cgo = select({
        ":network_plugins": True,
        "//conditions:default": False,
    }),
    bazel_clinkopts = select({
        ":network_plugins": ["-L external/libpluginstack"],
        "//conditions:default": [],
    }),
    bazel_copts = select({
        ":network_plugins": [
            "-march=native",
            "-I external/libpluginstack/lib/libtle_glue",
        ],
        "//conditions:default": [],
    }),
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
    ],
)

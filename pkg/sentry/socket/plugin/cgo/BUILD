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
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/abi/linux/errno",
    ],
)

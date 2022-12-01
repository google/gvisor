load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "testsuite",
    testonly = True,
    srcs = ["testsuite.go"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/lisafs",
        "//pkg/refs",
        "//pkg/unet",
        "@com_github_syndtr_gocapability//capability:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

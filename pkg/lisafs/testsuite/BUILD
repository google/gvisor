load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//visibility:public"],
    licenses = ["notice"],
)

go_library(
    name = "testsuite",
    testonly = True,
    srcs = ["testsuite.go"],
    importpath = "gvisor.dev/gvisor/pkg/lisafs/testsuite",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/lisafs",
        "//pkg/rand",
        "//pkg/refs",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

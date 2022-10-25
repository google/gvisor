load("//tools:defs.bzl", "go_library")

package(
    default_visibility = ["//:sandbox"],
    licenses = ["notice"],
)

go_library(
    name = "uds",
    testonly = 1,
    srcs = ["uds.go"],
    deps = [
        "//pkg/cleanup",
        "//pkg/log",
        "//pkg/unet",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "devices",
    srcs = [
        "device.go",
        "device_unix.go",
    ],
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)


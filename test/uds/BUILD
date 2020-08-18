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
        "//pkg/log",
        "//pkg/unet",
    ],
)

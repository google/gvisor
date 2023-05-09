load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "client",
    srcs = [
        "client.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/unet",
        "//pkg/urpc",
    ],
)

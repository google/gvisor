load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

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

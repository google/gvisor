load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "server",
    srcs = ["server.go"],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/log",
        "//pkg/sync",
        "//pkg/unet",
        "//pkg/urpc",
    ],
)

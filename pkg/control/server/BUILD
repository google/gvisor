load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

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

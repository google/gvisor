load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "channel",
    srcs = ["channel.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

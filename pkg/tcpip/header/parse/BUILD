load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "parse",
    srcs = ["parse.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

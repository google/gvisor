load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "loopback",
    srcs = ["loopback.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

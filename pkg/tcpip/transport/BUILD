load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "transport",
    srcs = [
        "datagram.go",
        "transport.go",
    ],
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip"],
)

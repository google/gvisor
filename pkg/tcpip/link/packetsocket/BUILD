load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "packetsocket",
    srcs = ["endpoint.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
    ],
)

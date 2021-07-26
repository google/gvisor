load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "network",
    srcs = [
        "endpoint.go",
        "endpoint_state.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

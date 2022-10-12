load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "xdp",
    srcs = [
        "endpoint.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/qdisc/fifo",
        "//pkg/tcpip/link/rawfile",
        "//pkg/tcpip/link/stopfd",
        "//pkg/tcpip/stack",
        "//pkg/xdp",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

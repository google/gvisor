load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "ethernet",
    srcs = ["ethernet.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
    ],
)

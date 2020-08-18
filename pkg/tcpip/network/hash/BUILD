load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "hash",
    srcs = ["hash.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/tcpip/header",
    ],
)

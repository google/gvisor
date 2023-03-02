load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "hash",
    srcs = ["hash.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/rand",
        "//pkg/tcpip/header",
    ],
)

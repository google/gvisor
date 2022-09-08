load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "checker",
    testonly = 1,
    srcs = ["checker.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/bufferv2",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

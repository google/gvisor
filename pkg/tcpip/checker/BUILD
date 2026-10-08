load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "checker",
    testonly = 1,
    srcs = ["checker.go"],
    importpath = "gvisor.dev/gvisor/pkg/tcpip/checker",
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/buffer",
        "//pkg/tcpip",
        "//pkg/tcpip/checksum",
        "//pkg/tcpip/header",
        "//pkg/tcpip/seqnum",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

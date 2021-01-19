load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ip",
    srcs = [
        "generic_multicast_protocol.go",
        "stats.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
    ],
)

go_test(
    name = "ip_test",
    size = "small",
    srcs = ["generic_multicast_protocol_test.go"],
    deps = [
        ":ip",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

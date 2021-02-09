load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "ip",
    srcs = ["duplicate_address_detection.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "ip_x_test",
    size = "small",
    srcs = ["duplicate_address_detection_test.go"],
    deps = [
        ":ip",
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/faketime",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

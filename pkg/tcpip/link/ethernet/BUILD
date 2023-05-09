load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

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

go_test(
    name = "ethernet_test",
    size = "small",
    srcs = ["ethernet_test.go"],
    deps = [
        ":ethernet",
        "//pkg/bufferv2",
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/channel",
        "//pkg/tcpip/stack",
        "@com_github_google_go_cmp//cmp:go_default_library",
    ],
)

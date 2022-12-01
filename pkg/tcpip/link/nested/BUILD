load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "nested",
    srcs = [
        "nested.go",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/sync",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "nested_test",
    size = "small",
    srcs = [
        "nested_test.go",
    ],
    deps = [
        "//pkg/refs",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/link/nested",
        "//pkg/tcpip/stack",
    ],
)

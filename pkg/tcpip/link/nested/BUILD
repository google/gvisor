load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "nested",
    srcs = [
        "capture.go",
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
    srcs = [
        "capture_test.go",
        "nested_test.go",
    ],
    deps = [
        ":nested",
        "//pkg/buffer",
        "//pkg/refs",
        "//pkg/refsvfs2",
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

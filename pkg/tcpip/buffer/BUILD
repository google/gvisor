load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "buffer",
    srcs = [
        "prependable.go",
        "view.go",
        "view_unsafe.go",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "buffer_x_test",
    size = "small",
    srcs = [
        "view_test.go",
    ],
    deps = [
        ":buffer",
        "//pkg/tcpip",
    ],
)

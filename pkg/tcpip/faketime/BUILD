load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "faketime",
    srcs = ["faketime.go"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/tcpip"],
)

go_test(
    name = "faketime_test",
    size = "small",
    srcs = [
        "faketime_test.go",
    ],
    deps = [
        "//pkg/tcpip/faketime",
    ],
)

load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "pipe",
    srcs = ["pipe.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "//pkg/tcpip/header",
        "//pkg/tcpip/stack",
    ],
)

go_test(
    name = "pipe_test",
    srcs = ["pipe_test.go"],
    library = ":pipe",
    deps = ["//pkg/tcpip"],
)

load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "fd",
    srcs = ["fd.go"],
    visibility = ["//visibility:public"],
)

go_test(
    name = "fd_test",
    size = "small",
    srcs = ["fd_test.go"],
    library = ":fd",
)

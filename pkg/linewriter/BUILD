load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "linewriter",
    srcs = ["linewriter.go"],
    visibility = ["//visibility:public"],
    deps = ["//pkg/sync"],
)

go_test(
    name = "linewriter_test",
    srcs = ["linewriter_test.go"],
    library = ":linewriter",
)

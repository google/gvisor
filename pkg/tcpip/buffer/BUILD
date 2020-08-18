load("//tools:defs.bzl", "go_library", "go_test")

package(licenses = ["notice"])

go_library(
    name = "buffer",
    srcs = [
        "prependable.go",
        "view.go",
    ],
    visibility = ["//visibility:public"],
)

go_test(
    name = "buffer_test",
    size = "small",
    srcs = [
        "prependable_test.go",
        "view_test.go",
    ],
    library = ":buffer",
)
